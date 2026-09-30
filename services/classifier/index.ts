import type { RiskClassifier } from '../../packages/core/types.js';

/** Broker-owned deterministic eligibility filter for the synthetic reviewed adapter.
 * This is deliberately limited to a fixed origin and read profile. Agent prose
 * does not create authority. Unknown contexts are uncertain and therefore block. */
export function syntheticClassifier(origin: string): RiskClassifier {
  return async (context, signal) => {
    if (signal.aborted) return 'uncertain';
    if (
      context.destination !== origin ||
      context.operation !== 'sign_in' ||
      context.action_profile !== 'synthetic_read_profile' ||
      JSON.stringify(context.factors) !== JSON.stringify(['password', 'totp'])
    )
      return 'uncertain';
    return {
      classification: 'safe',
      reason_codes: ['REVIEWED_SYNTHETIC_READ_PROFILE'],
      uncertainties: [],
    };
  };
}
