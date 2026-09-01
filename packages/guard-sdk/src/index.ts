/**
 * @sentinelreign/guard — embedded MCP security firewall.
 *
 * Detection runs in the host process through @sentinelreign/guard-core. No agent
 * traffic leaves the customer's network; the control plane sees only entitlement
 * and counters.
 */

export {
  Guard,
  DEFAULT_CONTROL_PLANE,
  HEADERLESS_DISABLED_CHECKS,
  SDK_VERSION,
  idOf,
  sanitizeRules,
} from './guard.js';
export type {
  GuardOptions,
  HeartbeatResponse,
  LicenseState,
  LicenseValidateResponse,
} from './guard.js';

export { expressGuard, wrap } from './middleware.js';
export type { ConnectRequest, ConnectResponse, McpHandler, WrapOptions } from './middleware.js';

// Re-exported so an embedder needs one dependency, not two.
export {
  GUARD_ERROR_CODES,
  RUBRIC_VERSION,
  buildBaseline,
  checkCount,
  evaluate,
  grade,
  hashToolDefinition,
  parseRequest,
  toJsonRpcError,
} from '@guard/core';
export type {
  CustomRule,
  Finding,
  GradeReport,
  GuardEvent,
  GuardPolicy,
  GuardPolicyWithSchemas,
  JsonRpcErrorResponse,
  JsonRpcRequest,
  ToolBaseline,
  ToolDefinition,
  Verdict,
} from '@guard/core';
