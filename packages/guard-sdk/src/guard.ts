/**
 * @sentinelreign/guard — the embedded SDK.
 *
 * Runs inside the vendor's own process. No traffic leaves their network: every
 * verdict comes from guard-core's pure `evaluate()`, executed in-process. The
 * control plane is contacted for TWO things only — entitlement and rule refresh
 * — and never for enforcement.
 *
 * Two fail-open concerns are deliberately separate, because conflating them is
 * how the previous prototype shipped a licence check that could never fire:
 *
 *   failOpenOnNetworkError   default TRUE   — the control plane being
 *                                             unreachable must not take the
 *                                             customer's server down.
 *   failOpenOnInvalidLicense default FALSE  — a revoked or expired licence is
 *                                             not an availability event. Turning
 *                                             this on disables the paid gate,
 *                                             which is why it is opt-in and
 *                                             logged when it takes effect.
 */

import {
  buildBaseline,
  evaluate,
  toJsonRpcError,
  type CustomRule,
  type GuardEvent,
  type GuardPolicyWithSchemas,
  type JsonRpcErrorResponse,
  type ToolBaseline,
  type ToolDefinition,
  type Verdict,
  verifyOfflineLicense,
} from '@guard/core';

/** Asserted equal to package.json's version by the test suite. Sent to the control plane. */
export const SDK_VERSION = '0.1.1';

export const DEFAULT_CONTROL_PLANE = 'https://guard.sentinelreign.com';

/**
 * stdio and in-process MCP transports carry no `Mcp-Method` / `Mcp-Name`
 * routing headers, so the header-agreement checks have nothing to compare
 * against. They are switched off for those transports — and ONLY those — rather
 * than being faked with headers synthesised from the body, which would make the
 * check pass without testing anything.
 */
export const HEADERLESS_DISABLED_CHECKS = ['L0.MISSING_NAME_HEADER'] as const;

export type LicenseState =
  /** `init()` has not resolved yet. Detection is live; the licence gate is not. */
  | 'uninitialised'
  /** No licence key: full local detection, no control-plane connection. The gate never denies. */
  | 'local'
  /** The control plane confirmed an active licence. */
  | 'active'
  /** The control plane answered, and the answer was no. */
  | 'invalid'
  /** The control plane could not be reached. */
  | 'unreachable';

/** `POST /api/v1/license/validate` response. */
export interface LicenseValidateResponse {
  active: boolean;
  planTier?: string;
  rules?: unknown;
  expiresAt?: string | null;
}

/** `POST /api/v1/heartbeat` response. */
export interface HeartbeatResponse {
  active: boolean;
  rules?: unknown;
}

export interface GuardOptions {
  /**
   * Optional. A licence key from the control plane. Set it ONLY to connect this
   * instance to the hosted SaaS — central rules, usage reporting, the dashboard.
   * WITHOUT a key the SDK runs fully local: every detection check, zero network
   * calls, the licence gate never denies. Detection is free and always on; the
   * key unlocks the managed connection, never the detection itself.
   */
  licenseKey?: string;
  /** Stable identifier for the MCP server. Only used when connecting to the control plane; defaults to `'local'`. */
  serverId?: string;
  /** Override for self-hosted control planes. */
  controlPlaneUrl?: string;
  /** Locally configured policy. Control-plane rules are appended to `customRules`. */
  policy?: GuardPolicyWithSchemas;
  /** Default `true`. A control plane that cannot be reached must not block traffic. */
  failOpenOnNetworkError?: boolean;
  /** Default `false`. Turning this on disables the paid entitlement gate. */
  failOpenOnInvalidLicense?: boolean;
  /** Default 300_000 (5 min). `0` disables the heartbeat entirely. */
  heartbeatIntervalMs?: number;
  /** Default 5_000. Applies to both control-plane calls. */
  requestTimeoutMs?: number;
  /** White-label the block message for OEM embedding, e.g. `'Acme Security'`. */
  brand?: string;
  /** `'stdio'` disables the header-agreement checks. See HEADERLESS_DISABLED_CHECKS. */
  transport?: 'http' | 'stdio';
  /** Control-plane and licence diagnostics. Defaults to `console.error`. */
  onDiagnostic?: (message: string, error?: unknown) => void;
  /**
   * Air-gapped operation. A signed offline licence token minted by the control
   * plane. When set (with `offlineLicensePublicKey`), the SDK verifies it locally
   * and makes NO network call at all — no validate, no heartbeat. For deployments
   * that cannot reach the control plane.
   */
  offlineLicense?: string;
  /** The Ed25519 public key (PEM) that verifies `offlineLicense`. */
  offlineLicensePublicKey?: string;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * The control plane is a trust boundary even though we own it. Rules that do not
 * match the shape are dropped rather than handed to the engine.
 */
export function sanitizeRules(input: unknown): CustomRule[] {
  if (!Array.isArray(input)) return [];
  const out: CustomRule[] = [];
  for (const raw of input) {
    if (!isRecord(raw)) continue;
    const { id, name, pattern, action, enabled, argumentPaths } = raw;
    if (typeof id !== 'string' || typeof name !== 'string' || typeof pattern !== 'string') continue;
    if (action !== 'BLOCK' && action !== 'WARN' && action !== 'ALLOW') continue;
    const paths = Array.isArray(argumentPaths) ? argumentPaths.filter((p) => typeof p === 'string') : undefined;
    out.push({
      id,
      name,
      pattern,
      action,
      enabled: enabled !== false,
      ...(paths && paths.length > 0 ? { argumentPaths: paths } : {}),
    });
  }
  return out;
}

/** The JSON-RPC id of a request, or `null` when there is not one. */
export function idOf(body: unknown): string | number | null {
  if (!isRecord(body)) return null;
  const id = body.id;
  return typeof id === 'string' || typeof id === 'number' ? id : null;
}

export class Guard {
  readonly serverId: string;

  private readonly options: Required<
    Pick<
      GuardOptions,
      | 'controlPlaneUrl'
      | 'failOpenOnNetworkError'
      | 'failOpenOnInvalidLicense'
      | 'heartbeatIntervalMs'
      | 'requestTimeoutMs'
      | 'transport'
    >
  > &
    GuardOptions;

  private state: LicenseState = 'uninitialised';
  private tier: string | undefined;
  private remoteRules: CustomRule[] = [];
  private baseline: ToolBaseline | undefined;
  private effective: GuardPolicyWithSchemas;
  private timer: ReturnType<typeof setInterval> | undefined;
  private bootstrap: Promise<void> | undefined;
  private processed = 0;
  private blocked = 0;
  private announcedDenial = false;

  /** Does NOT touch the network. Call `init()` (or use `Guard.create`). */
  constructor(options: GuardOptions) {
    // No licenceKey is valid: it means unlicensed local mode (full detection,
    // no network). serverId only matters when connecting to the control plane.
    this.serverId = options.serverId ?? 'local';
    this.options = {
      ...options,
      controlPlaneUrl: (options.controlPlaneUrl ?? DEFAULT_CONTROL_PLANE).replace(/\/+$/, ''),
      failOpenOnNetworkError: options.failOpenOnNetworkError ?? true,
      failOpenOnInvalidLicense: options.failOpenOnInvalidLicense ?? false,
      heartbeatIntervalMs: options.heartbeatIntervalMs ?? 300_000,
      requestTimeoutMs: options.requestTimeoutMs ?? 5_000,
      transport: options.transport ?? 'http',
    };
    this.baseline = options.policy?.baseline;
    this.effective = this.composePolicy();
  }

  /** Construct and await rule load in one step. */
  static async create(options: GuardOptions): Promise<Guard> {
    const guard = new Guard(options);
    await guard.init();
    return guard;
  }

  /**
   * Resolves once the licence has been checked and control-plane rules loaded.
   * Idempotent: concurrent and repeated calls share one round trip.
   */
  init(): Promise<void> {
    this.bootstrap ??= this.boot();
    return this.bootstrap;
  }

  get licenseState(): LicenseState {
    return this.state;
  }

  get planTier(): string | undefined {
    return this.tier;
  }

  /** Counters since the last heartbeat. */
  get counters(): { processed: number; blocked: number } {
    return { processed: this.processed, blocked: this.blocked };
  }

  /** The policy `evaluate()` is actually being called with. */
  get policy(): GuardPolicyWithSchemas {
    return this.effective;
  }

  /**
   * Evaluate one event. Pure, in-process, no network — the verdict is identical
   * to the one the hosted gateway would return for the same event and policy.
   *
   * Before `init()` resolves this still enforces, using the built-in checks and
   * any locally configured policy; only control-plane rules are missing. It
   * never silently passes everything, which is what an un-awaited constructor
   * handshake did in the prototype.
   */
  verify(event: GuardEvent): Verdict {
    this.processed++;

    if (this.licenceDenies()) {
      this.blocked++;
      // A block the operator cannot see is worse than no block at all.
      this.announceDenialOnce();
      return { decision: 'block', findings: [] };
    }

    const verdict = evaluate(event, this.effective);

    // Trust on first use: the first inventory a server advertises becomes the
    // pin, so a later mutation is a rug pull. An explicitly configured baseline
    // (an approved inventory) is never overwritten.
    if (event.kind === 'tools_list' && !this.baseline && verdict.decision !== 'block') {
      this.pinBaseline(event.tools);
    }

    if (verdict.decision === 'block') this.blocked++;
    return verdict;
  }

  /** Freeze this inventory as the approved baseline for rug-pull detection. */
  pinBaseline(tools: ToolDefinition[]): ToolBaseline {
    this.baseline = buildBaseline(tools);
    this.effective = this.composePolicy();
    return this.baseline;
  }

  /** Render a blocking verdict as a JSON-RPC error, white-labelled when `brand` is set. */
  errorFor(verdict: Verdict, id: string | number | null): JsonRpcErrorResponse {
    const error = toJsonRpcError(verdict, id);
    if (this.options.brand) {
      error.error.message = error.error.message.replace('SentinelAgent Guard', this.options.brand);
    }
    return error;
  }

  /** Stop the heartbeat. The timer is unref'd, so this is for tidiness, not liveness. */
  close(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  /* ------------------------------------------------------------- internals */

  private licenceDenies(): boolean {
    if (this.state === 'invalid') return !this.options.failOpenOnInvalidLicense;
    if (this.state === 'unreachable') return !this.options.failOpenOnNetworkError;
    return false; // 'active', 'local' (unlicensed), and 'uninitialised' never deny.
  }

  private announceDenialOnce(): void {
    if (this.announcedDenial) return;
    this.announcedDenial = true;
    this.diagnose(
      `licence state is "${this.state}" — every request is being blocked. ` +
        (this.state === 'unreachable'
          ? 'Set failOpenOnNetworkError: true to serve traffic while the control plane is unreachable.'
          : 'Renew the licence, or set failOpenOnInvalidLicense: true to disable the entitlement gate.'),
    );
  }

  private composePolicy(): GuardPolicyWithSchemas {
    const configured = this.options.policy ?? {};
    const disabled = new Set(configured.disabledChecks ?? []);
    if (this.options.transport === 'stdio') for (const c of HEADERLESS_DISABLED_CHECKS) disabled.add(c);
    return {
      ...configured,
      ...(this.baseline ? { baseline: this.baseline } : {}),
      customRules: [...(configured.customRules ?? []), ...this.remoteRules],
      ...(disabled.size > 0 ? { disabledChecks: [...disabled] } : {}),
    };
  }

  private diagnose(message: string, error?: unknown): void {
    const sink = this.options.onDiagnostic;
    if (sink) sink(message, error);
    else console.error(`[sentinelagent-guard] ${message}`, error ?? '');
  }

  private async boot(): Promise<void> {
    // Air-gapped: verify the signed offline licence locally and never touch the
    // network — no validate, no heartbeat.
    if (this.options.offlineLicense) {
      this.applyOfflineLicence();
      return;
    }
    // Unlicensed local mode: no key means no control-plane connection at all —
    // full detection runs, the gate never denies, nothing leaves the process.
    if (!this.options.licenseKey) {
      this.state = 'local';
      return;
    }
    await this.validate();
    if (this.options.heartbeatIntervalMs > 0 && !this.timer) {
      this.timer = setInterval(() => void this.heartbeat(), this.options.heartbeatIntervalMs);
      // Never keep a host process alive on our account.
      this.timer.unref?.();
    }
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.options.controlPlaneUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.options.requestTimeoutMs),
    });
    if (!res.ok) throw new Error(`control plane responded ${res.status}`);
    return (await res.json()) as T;
  }

  private applyLicence(active: boolean, rules: unknown, expiresAt?: string | null): void {
    const expired = typeof expiresAt === 'string' && Number.isFinite(Date.parse(expiresAt)) && Date.parse(expiresAt) < Date.now();
    this.state = active && !expired ? 'active' : 'invalid';
    // An omitted `rules` field means "unchanged", not "delete every rule".
    if (Array.isArray(rules)) this.remoteRules = sanitizeRules(rules);
    this.effective = this.composePolicy();
    if (this.state === 'active') this.announcedDenial = false;
  }

  private applyOfflineLicence(): void {
    const token = this.options.offlineLicense;
    const pub = this.options.offlineLicensePublicKey;
    if (!token || !pub) {
      this.state = 'invalid';
      this.diagnose('offlineLicense requires offlineLicensePublicKey to verify it.');
      this.effective = this.composePolicy();
      return;
    }
    const licence = verifyOfflineLicense(token, pub);
    if (!licence) {
      this.state = 'invalid';
      this.diagnose('the offline licence is invalid or expired.');
      this.effective = this.composePolicy();
      return;
    }
    this.tier = licence.plan;
    // No remote rules in air-gapped mode: rules come from the local `policy`.
    this.state = 'active';
    this.effective = this.composePolicy();
    this.announcedDenial = false;
  }

  private async validate(): Promise<void> {
    try {
      const res = await this.post<LicenseValidateResponse>('/api/v1/license/validate', {
        licenseKey: this.options.licenseKey,
        serverId: this.serverId,
        sdkVersion: SDK_VERSION,
      });
      this.tier = typeof res.planTier === 'string' ? res.planTier : undefined;
      this.applyLicence(res.active === true, res.rules, res.expiresAt);
      if (this.state === 'invalid') this.diagnose('control plane reports the licence is not active.');
    } catch (err) {
      // A network failure is an availability event, not an entitlement answer.
      this.state = 'unreachable';
      this.diagnose('licence validation could not reach the control plane.', err);
    }
  }

  private async heartbeat(): Promise<void> {
    const processed = this.processed;
    const blocked = this.blocked;
    try {
      const res = await this.post<HeartbeatResponse>('/api/v1/heartbeat', {
        licenseKey: this.options.licenseKey,
        serverId: this.serverId,
        sdkVersion: SDK_VERSION,
        processedCount: processed,
        blockedCount: blocked,
      });
      // Only counters the control plane has accepted are cleared.
      this.processed -= processed;
      this.blocked -= blocked;
      this.applyLicence(res.active === true, res.rules);
    } catch (err) {
      this.state = 'unreachable';
      this.diagnose('heartbeat could not reach the control plane.', err);
    }
  }
}
