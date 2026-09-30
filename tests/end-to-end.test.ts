import { describe, expect, it } from 'vitest';
import { runSyntheticFlow } from '../scripts/demo.js';
import { SYNTHETIC_CREDENTIAL } from '../services/secret-service/synthetic-fixture.js';
describe('synthetic end-to-end authorization and browser flow', () => {
  for (const mode of ['manual', 'safe', 'auto'] as const)
    it(`${mode} verifies the account and returns only a restricted profile`, async () => {
      const flow = await runSyntheticFlow(mode);
      expect(flow.initialState).toBe(mode === 'auto' ? 'AUTHORIZED' : 'AWAITING_APPROVAL');
      expect(flow.status.state).toBe('SUCCEEDED');
      expect(flow.profile).toEqual({
        account_id: 'acct_synthetic',
        display_name: 'Synthetic Owner',
        message: 'Synthetic read access verified.',
      });
      expect(flow.submissions).toEqual({ password: 1, totp: 1 });
      const output = JSON.stringify(flow);
      for (const secret of [SYNTHETIC_CREDENTIAL.password, SYNTHETIC_CREDENTIAL.totpSeed])
        expect(output).not.toContain(secret);
      expect(
        flow.audit.some(
          (e) => e.authorizationKind === (mode === 'auto' ? 'DELEGATED_AUTO' : 'OWNER_DEVICE'),
        ),
      ).toBe(true);
    });
});
