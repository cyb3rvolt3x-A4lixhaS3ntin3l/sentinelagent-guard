/**
 * @sentinelreign/guard-core — the deterministic detection engine.
 *
 * Zero runtime dependencies. Pure functions. No LLM in the request path.
 */

export * from './types.js';

export { CHECKS, checkCount, getCheck, actionForSeverity, finding } from './checks.js';

export {
  KNOWN_METHODS,
  REMOVED_METHODS,
  GUARD_ERROR_CODES,
  toJsonRpcError,
  parseRequest,
  checkProtocol,
} from './layer0-protocol.js';
export type { JsonRpcErrorResponse, ParsedRequest } from './layer0-protocol.js';

export {
  canonicalJson,
  hashToolDefinition,
  buildBaseline,
  findConcealment,
  decodeTagBlock,
  checkTools,
} from './layer1-tools.js';
export type { ConcealmentHit } from './layer1-tools.js';

export {
  MAX_INSPECTED_LENGTH,
  validateRulePattern,
  validateAgainstSchema,
  collectStringLeaves,
  checkPolicy,
} from './layer2-policy.js';
export type { PatternValidation, SchemaViolation, StringLeaf } from './layer2-policy.js';

export { shannonEntropy, checkResponse } from './layer3-response.js';
export type { ResponseResult } from './layer3-response.js';

export { RUBRIC_VERSION, SEVERITY_WEIGHTS, PER_CHECK_SATURATION, scoreFindings, gradeForScore, grade } from './mcpgrade.js';

export { evaluate } from './engine.js';
export { verifyOfflineLicense, OFFLINE_PREFIX } from './offline-license.js';
export type { OfflineLicense } from './offline-license.js';
