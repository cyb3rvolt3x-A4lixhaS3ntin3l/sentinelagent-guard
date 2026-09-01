/**
 * @sentinelreign/guard-proxy — stdio sidecar and mcpgrade scanner.
 *
 * The CLI is the product; these exports exist so the same proxy can be embedded
 * in a host that already manages its own child processes.
 */

export { lineReader, runProxy, STDIO_DISABLED_CHECKS } from './proxy.js';
export type { Direction, ProxyEvent, ProxyHandle, ProxyOptions } from './proxy.js';

export {
  SEVERITY_ORDER,
  ScanError,
  atOrAbove,
  colorEnabled,
  describeTarget,
  parseTarget,
  renderJson,
  renderReport,
  scan,
  worstSeverity,
} from './scan.js';
export type { ScanReport, Target } from './scan.js';
