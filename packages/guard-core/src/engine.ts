/**
 * Composition. The only entry point any deployment shape should call.
 *
 * Pure: no I/O, no clock, no globals mutated. The same (event, policy) pair
 * always yields the same Verdict, which is what makes the audit log replayable
 * and the hosted gateway and the embedded SDK agree by construction.
 */

import { checkProtocol, parseRequest } from './layer0-protocol.js';
import { checkTools } from './layer1-tools.js';
import { checkPolicy } from './layer2-policy.js';
import { checkResponse } from './layer3-response.js';
import { grade } from './mcpgrade.js';
import type { Decision, Finding, GuardEvent, GuardPolicy, Verdict } from './types.js';

function decide(findings: Finding[]): Decision {
  if (findings.some((f) => f.action === 'BLOCK')) return 'block';
  if (findings.some((f) => f.action === 'WARN')) return 'warn';
  return 'allow';
}

export function evaluate(event: GuardEvent, policy: GuardPolicy): Verdict {
  let findings: Finding[] = [];
  let redactedBody: unknown;

  switch (event.kind) {
    case 'request': {
      findings = checkProtocol(event);
      const parsed = parseRequest(event.body);
      // L2 needs a method and params; a body too broken to parse has already
      // produced an L0 finding and there is nothing further to inspect.
      if (parsed) findings = findings.concat(checkPolicy(parsed.method, parsed.params, policy));
      break;
    }
    case 'tools_list':
      findings = checkTools(event.tools, policy);
      break;
    case 'response': {
      const result = checkResponse(event, policy);
      findings = result.findings;
      redactedBody = result.redactedBody;
      break;
    }
  }

  const disabled = policy.disabledChecks;
  if (disabled && disabled.length > 0) {
    const off = new Set(disabled);
    findings = findings.filter((f) => !off.has(f.check));
  }

  return {
    decision: decide(findings),
    findings,
    ...(redactedBody === undefined ? {} : { redactedBody }),
  };
}

export { grade };
