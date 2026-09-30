import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { chromium, type Browser, type Page } from 'playwright';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

const fingerprint = 'a'.repeat(64);
const device = {
  id: 'device_synthetic',
  name: 'My iPhone',
  status: 'ACTIVE',
  key_fingerprint: fingerprint,
};
const request = {
  request_id: 'req_synthetic',
  state: 'AWAITING_APPROVAL',
  destination: 'http://127.0.0.1:3212',
  account_display_name: 'Synthetic account',
  client_display_name: 'Local agent',
  purpose: 'Read the synthetic profile',
  session_action_profile: 'synthetic_read_profile',
};
const overview = () => ({
  requests: [] as Array<typeof request>,
  devices: [structuredClone(device)],
  policies: [
    {
      id: 'policy_owner_synthetic_42',
      mode: 'manual',
      version: 7,
      enabled: true,
      auto_delegation_available: false,
    },
  ],
  synthetic_only: true,
  production_credentials_enabled: false,
});
const browserInstalled = existsSync(chromium.executablePath());

describe.runIf(browserInstalled)(
  'owner-console interaction boundaries in sandboxed Chromium',
  () => {
    let browser: Browser;
    const pages: Page[] = [];
    beforeAll(async () => {
      browser = await chromium.launch({ chromiumSandbox: true });
    });
    afterEach(async () => {
      for (const page of pages.splice(0)) await page.context().close();
    });
    afterAll(async () => {
      await browser?.close();
    });
    async function setup(initial = overview()) {
      const assets = new Map(
        await Promise.all(
          ['index.html', 'app.js', 'style.css'].map(
            async (name) =>
              [
                name === 'index.html' ? '/' : `/${name}`,
                await readFile(new URL(`../apps/admin-web/${name}`, import.meta.url), 'utf8'),
              ] as const,
          ),
        ),
      );
      const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
      pages.push(page);
      await page.clock.install();
      const state = {
        overview: initial,
        fail: false,
        posts: [] as string[],
        postBodies: [] as Array<{ path: string; body: Record<string, unknown> }>,
        modeError: undefined as string | undefined,
        modeResponse: undefined as (typeof initial.policies)[number] | undefined,
        loseModeResponse: false,
        holdModeSave: false,
        releaseModeSave: undefined as (() => void) | undefined,
        errors: [] as string[],
      };
      page.on('pageerror', (error) => state.errors.push(error.message));
      await page.route('http://owner.test/**', async (route) => {
        const path = new URL(route.request().url()).pathname;
        if (route.request().method() === 'POST') {
          state.posts.push(path);
          const body = route.request().postDataJSON() as Record<string, unknown>;
          state.postBodies.push({ path, body });
          if (path.startsWith('/admin/policies/')) {
            if (state.holdModeSave)
              await new Promise<void>((resolve) => {
                state.releaseModeSave = resolve;
              });
            const id = decodeURIComponent(path.split('/')[3]!);
            const policy = state.overview.policies.find((row) => row.id === id);
            if (state.modeResponse) {
              await route.fulfill({ json: state.modeResponse });
              return;
            }
            if (state.modeError || !policy || body.expected_version !== policy.version) {
              await route.fulfill({
                status: 400,
                json: { error: state.modeError || 'POLICY_DENIED' },
              });
              return;
            }
            if (body.mode !== policy.mode) {
              policy.mode = body.mode as string;
              policy.version++;
            }
            if (state.loseModeResponse) {
              await route.abort('failed');
              return;
            }
            await route.fulfill({ json: policy });
            return;
          }
          if (path === '/admin/devices/device_synthetic/confirm')
            state.overview.devices[0]!.status = 'ACTIVE';
          if (path === '/admin/pairings') {
            await route.fulfill({
              json: {
                pairing_code: 'SYNTHETIC-private-pairing-code',
                expires_at: new Date(Date.now() + 20000).toISOString(),
              },
            });
            return;
          }
          await route.fulfill({ json: { accepted: true } });
          return;
        }
        if (path === '/admin/overview') {
          await route.fulfill(
            state.fail
              ? { status: 503, json: { error: 'SYNTHETIC-untrusted-raw-error' } }
              : { json: state.overview },
          );
          return;
        }
        const body = assets.get(path);
        await route.fulfill({
          status: body === undefined ? 404 : 200,
          contentType:
            path === '/app.js'
              ? 'application/javascript'
              : path === '/style.css'
                ? 'text/css'
                : 'text/html',
          body: body || '',
        });
      });
      await page.goto('http://owner.test/');
      await page.getByLabel('Owner token', { exact: true }).fill('SYNTHETIC-owner-token');
      await page.getByRole('button', { name: 'Connect', exact: true }).click();
      await expect.poll(() => page.locator('#dashboard').isVisible()).toBe(true);
      return { page, state };
    }

    it('prioritizes pending approvals, keeps mode visible and collapses activity/devices without rendering agent HTML', async () => {
      const data = overview();
      data.requests = [
        { ...request, request_id: 'req_done', state: 'SUCCEEDED' },
        { ...request, request_id: 'req_running', state: 'EXECUTING' },
        {
          ...request,
          account_display_name: '<img src=x onerror=alert(1)>',
          purpose: '<script>alert(1)</script>',
        },
      ];
      const { page, state } = await setup(data);
      expect(await page.locator('#requests article').count()).toBe(2);
      expect(await page.locator('#requests article').first().textContent()).toContain(
        'Waiting for approval',
      );
      expect(await page.locator('#requests img, #requests script').count()).toBe(0);
      expect(await page.locator('#requests').textContent()).toContain('<script>alert(1)</script>');
      expect(await page.locator('#history').getAttribute('open')).toBeNull();
      expect(await page.locator('#settings').getAttribute('open')).toBeNull();
      expect(await page.getByRole('radio', { name: 'Manual', exact: true }).isVisible()).toBe(true);
      expect(await page.locator('#settings > summary').textContent()).toContain('Devices');
      expect(await page.locator('#recent-requests article').count()).toBe(1);
      expect(await page.getByRole('button', { name: 'Deny', exact: true }).count()).toBe(1);
      expect(await page.getByRole('button', { name: 'Approve', exact: true }).count()).toBe(0);
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
      ).toBe(true);
      expect(state.posts).toEqual([]);
      expect(state.errors).toEqual([]);
    });

    it('shows the complete key fingerprint and keeps confirmation separate from comparison and polling', async () => {
      const data = overview();
      data.devices[0]!.status = 'PENDING_CONFIRMATION';
      const { page, state } = await setup(data);
      const confirm = page.getByRole('button', { name: 'Confirm device', exact: true });
      expect(await page.locator('#pending-devices code').textContent()).toBe(fingerprint);
      expect(await confirm.isDisabled()).toBe(true);
      await page.getByRole('checkbox').check();
      expect(await confirm.isEnabled()).toBe(true);
      await page.clock.runFor(10001);
      expect(state.posts).toEqual([]);
      expect(await page.getByRole('checkbox').isChecked()).toBe(true);
      await confirm.click();
      await expect.poll(() => page.locator('#setup').isHidden()).toBe(true);
      expect(state.posts).toEqual(['/admin/devices/device_synthetic/confirm']);
      expect(await page.locator('#connection-status').textContent()).toBe('Ready');
      expect(state.errors).toEqual([]);
    });

    it('clears stale polling errors on recovery without echoing a raw error or storing the token', async () => {
      const { page, state } = await setup();
      state.fail = true;
      await page.clock.runFor(10001);
      await expect.poll(() => page.locator('#notice').isVisible()).toBe(true);
      expect(await page.locator('#notice').textContent()).not.toContain(
        'SYNTHETIC-untrusted-raw-error',
      );
      expect(await page.locator('#connection-status').textContent()).toBe('Reconnecting');
      state.fail = false;
      await page.clock.runFor(10001);
      await expect.poll(() => page.locator('#notice').isHidden()).toBe(true);
      expect(await page.locator('#connection-status').textContent()).toBe('Ready');
      expect(await page.locator('#token').inputValue()).toBe('');
      expect(
        await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length })),
      ).toEqual({ local: 0, session: 0 });
      await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
      expect(await page.locator('#dashboard').isHidden()).toBe(true);
      expect(await page.locator('#requests article, #devices article').count()).toBe(0);
      expect(state.errors).toEqual([]);
    });

    it('masks one-use pairing codes and clears them when a device arrives or the code expires', async () => {
      const data = overview();
      data.devices = [];
      const { page, state } = await setup(data);
      await page.getByRole('button', { name: 'Pair iPhone', exact: true }).click();
      await expect.poll(() => page.locator('#pairing').isVisible()).toBe(true);
      expect(await page.locator('#pairing-code').getAttribute('type')).toBe('password');
      expect(await page.locator('#notice').textContent()).not.toContain(
        'SYNTHETIC-private-pairing-code',
      );
      state.overview.devices = [{ ...device, status: 'PENDING_CONFIRMATION' }];
      await page.clock.runFor(10001);
      await expect.poll(() => page.locator('#pairing').isHidden()).toBe(true);
      expect(await page.locator('#pairing-code').inputValue()).toBe('');
      await page.locator('#settings > summary').click();
      await page.getByRole('button', { name: 'Pair another iPhone', exact: true }).click();
      await expect.poll(() => page.locator('#pairing').isVisible()).toBe(true);
      await page.clock.runFor(30001);
      await expect.poll(() => page.locator('#pairing').isHidden()).toBe(true);
      expect(await page.locator('#pairing-code').inputValue()).toBe('');
      expect(state.posts).toEqual(['/admin/pairings', '/admin/pairings']);
      expect(state.errors).toEqual([]);
    });

    it('applies only an explicit reviewed mode change with the server policy ID/version and prevents duplicate submits', async () => {
      const data = overview();
      data.policies[0]!.id = 'policy_actual_owner_binding_93';
      data.policies[0]!.version = 19;
      const { page, state } = await setup(data);
      await page.getByRole('radio', { name: 'Safe', exact: true }).check();
      expect(state.posts).toEqual([]);
      expect(await page.locator('.current-mode').textContent()).toBe('Current: Manual');
      expect(await page.locator('.mode-review').textContent()).toContain(
        'Pending requests will be cancelled and existing sessions ended.',
      );
      state.holdModeSave = true;
      const apply = page.getByRole('button', { name: 'Apply change', exact: true });
      await apply.click();
      await expect.poll(() => state.postBodies.length).toBe(1);
      expect(state.postBodies[0]).toEqual({
        path: '/admin/policies/policy_actual_owner_binding_93/mode',
        body: { mode: 'safe', expected_version: 19 },
      });
      expect(await page.locator('.current-mode').textContent()).toBe('Current: Manual');
      expect(await page.getByRole('button', { name: 'Applying…', exact: true }).isDisabled()).toBe(
        true,
      );
      await page.getByRole('button', { name: 'Applying…', exact: true }).dispatchEvent('click');
      expect(state.posts).toHaveLength(1);
      state.releaseModeSave!();
      await expect.poll(() => page.locator('.current-mode').textContent()).toBe('Current: Safe');
      expect(await page.getByRole('radio', { name: 'Safe', exact: true }).isChecked()).toBe(true);
      expect(await page.locator('.mode-review').isHidden()).toBe(true);
      expect(state.overview.policies[0]!.version).toBe(20);
      expect(state.errors).toEqual([]);
    });

    it('preserves a mode draft through polling and requires explicit review of a newer policy version', async () => {
      const { page, state } = await setup();
      await page.getByRole('radio', { name: 'Safe', exact: true }).check();
      state.overview.requests = [{ ...request }];
      await page.clock.runFor(2001);
      await expect.poll(() => page.locator('#requests article').count()).toBe(1);
      expect(await page.getByRole('radio', { name: 'Safe', exact: true }).isChecked()).toBe(true);
      expect(await page.locator('.current-mode').textContent()).toBe('Current: Manual');
      state.overview.policies[0]!.mode = 'auto';
      state.overview.policies[0]!.version = 8;
      await page.clock.runFor(2001);
      await expect.poll(() => page.locator('.current-mode').textContent()).toBe('Current: Auto');
      expect(await page.getByRole('radio', { name: 'Safe', exact: true }).isChecked()).toBe(true);
      expect(
        await page.getByRole('button', { name: 'Apply change', exact: true }).isDisabled(),
      ).toBe(true);
      expect(state.posts).toEqual([]);
      await page.getByRole('button', { name: 'Review latest', exact: true }).click();
      expect(state.posts).toEqual([]);
      await page.getByRole('button', { name: 'Apply change', exact: true }).click();
      await expect.poll(() => page.locator('.current-mode').textContent()).toBe('Current: Safe');
      expect(state.postBodies).toEqual([
        {
          path: '/admin/policies/policy_owner_synthetic_42/mode',
          body: { mode: 'safe', expected_version: 8 },
        },
      ]);
      expect(state.errors).toEqual([]);
    });

    it('refreshes current state after a stale save while retaining the draft and requiring a separate retry', async () => {
      const { page, state } = await setup();
      await page.getByRole('radio', { name: 'Auto', exact: true }).check();
      state.overview.policies[0]!.mode = 'safe';
      state.overview.policies[0]!.version = 8;
      await page.getByRole('button', { name: 'Apply change', exact: true }).click();
      await expect.poll(() => page.locator('.current-mode').textContent()).toBe('Current: Safe');
      await expect
        .poll(() => page.locator('.mode-message').textContent())
        .toContain('Save not confirmed');
      expect(await page.getByRole('radio', { name: 'Auto', exact: true }).isChecked()).toBe(true);
      expect(
        await page.getByRole('button', { name: 'Apply change', exact: true }).isDisabled(),
      ).toBe(true);
      expect(state.postBodies).toEqual([
        {
          path: '/admin/policies/policy_owner_synthetic_42/mode',
          body: { mode: 'auto', expected_version: 7 },
        },
      ]);
      await page.clock.runFor(4001);
      expect(await page.locator('.mode-message').textContent()).toContain('Save not confirmed');
      expect(state.posts).toHaveLength(1);
      await page.getByRole('button', { name: 'Review latest', exact: true }).click();
      expect(state.posts).toHaveLength(1);
      await page.getByRole('button', { name: 'Apply change', exact: true }).click();
      await expect.poll(() => page.locator('.current-mode').textContent()).toBe('Current: Auto');
      expect(state.postBodies[1]!.body).toEqual({ mode: 'auto', expected_version: 8 });
      expect(state.errors).toEqual([]);
    });

    it('shows blocked Auto semantics without creating a delegation or switching until Apply', async () => {
      const { page, state } = await setup();
      await page.getByRole('radio', { name: 'Auto', exact: true }).check();
      expect(await page.locator('.auto-notice').textContent()).toContain(
        'Auto requests are blocked without a matching owner delegation.',
      );
      expect(await page.locator('.auto-notice').textContent()).toContain(
        'does not create, expand or renew',
      );
      expect(await page.locator('.mode-description').textContent()).toContain(
        'exact existing owner delegation',
      );
      await page.clock.runFor(4001);
      expect(state.posts).toEqual([]);
      expect(await page.locator('.current-mode').textContent()).toBe('Current: Manual');
      expect(await page.getByRole('checkbox').count()).toBe(0);
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
      ).toBe(true);
      await page.getByRole('button', { name: 'Apply change', exact: true }).click();
      await expect.poll(() => page.locator('.current-mode').textContent()).toBe('Current: Auto');
      expect(state.posts).toEqual(['/admin/policies/policy_owner_synthetic_42/mode']);
      expect(await page.locator('.auto-notice').isVisible()).toBe(true);
      expect(state.errors).toEqual([]);
    });

    it('resolves a draft applied by another owner and binds a new selection to that fresh version', async () => {
      const { page, state } = await setup();
      await page.getByRole('radio', { name: 'Safe', exact: true }).check();
      state.overview.policies[0]!.mode = 'safe';
      state.overview.policies[0]!.version = 8;
      await page.clock.runFor(2001);
      await expect.poll(() => page.locator('.current-mode').textContent()).toBe('Current: Safe');
      expect(await page.locator('.mode-review').isHidden()).toBe(true);
      expect(state.posts).toEqual([]);
      await page.getByRole('radio', { name: 'Auto', exact: true }).check();
      expect(
        await page.getByRole('button', { name: 'Apply change', exact: true }).isEnabled(),
      ).toBe(true);
      await page.getByRole('button', { name: 'Apply change', exact: true }).click();
      await expect.poll(() => page.locator('.current-mode').textContent()).toBe('Current: Auto');
      expect(state.postBodies).toEqual([
        {
          path: '/admin/policies/policy_owner_synthetic_42/mode',
          body: { mode: 'auto', expected_version: 8 },
        },
      ]);
      expect(state.errors).toEqual([]);
    });

    it('rejects a changed-mode response with an unchanged version instead of displaying it as applied', async () => {
      const { page, state } = await setup();
      state.modeResponse = { ...state.overview.policies[0]!, mode: 'safe', version: 7 };
      await page.getByRole('radio', { name: 'Safe', exact: true }).check();
      await page.getByRole('button', { name: 'Apply change', exact: true }).click();
      await expect
        .poll(() => page.locator('.mode-message').textContent())
        .toContain('Save not confirmed');
      expect(await page.locator('.current-mode').textContent()).toBe('Current: Manual');
      expect(await page.getByRole('radio', { name: 'Safe', exact: true }).isChecked()).toBe(true);
      expect(
        await page.getByRole('button', { name: 'Apply change', exact: true }).isDisabled(),
      ).toBe(true);
      expect(state.posts).toHaveLength(1);
      expect(state.errors).toEqual([]);
    });

    it('reconciles a lost save response from fresh server state without a stale draft or automatic retry', async () => {
      const { page, state } = await setup();
      state.loseModeResponse = true;
      await page.getByRole('radio', { name: 'Safe', exact: true }).check();
      await page.getByRole('button', { name: 'Apply change', exact: true }).click();
      await expect.poll(() => page.locator('.current-mode').textContent()).toBe('Current: Safe');
      await expect
        .poll(() => page.getByRole('radio', { name: 'Safe', exact: true }).isEnabled())
        .toBe(true);
      expect(await page.locator('.mode-review').isHidden()).toBe(true);
      expect(await page.locator('.mode-message').isHidden()).toBe(true);
      await page.clock.runFor(4001);
      expect(state.postBodies).toEqual([
        {
          path: '/admin/policies/policy_owner_synthetic_42/mode',
          body: { mode: 'safe', expected_version: 7 },
        },
      ]);
      expect(state.overview.policies[0]!.version).toBe(8);
      expect(state.errors).toEqual([]);
    });

    it('does not display a failed save as applied and clears all policy drafts on disconnect', async () => {
      const { page, state } = await setup();
      state.modeError = 'SECURITY_STATE_UNPERSISTED';
      await page.getByRole('radio', { name: 'Safe', exact: true }).check();
      await page.getByRole('button', { name: 'Apply change', exact: true }).click();
      await expect
        .poll(() => page.locator('.mode-message').textContent())
        .toContain('security state could not be persisted');
      expect(await page.locator('.current-mode').textContent()).toBe('Current: Manual');
      expect(await page.getByRole('radio', { name: 'Safe', exact: true }).isChecked()).toBe(true);
      expect(
        await page.getByRole('button', { name: 'Apply change', exact: true }).isDisabled(),
      ).toBe(true);
      await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
      expect(await page.locator('#policies').textContent()).toBe('');
      await page.getByLabel('Owner token', { exact: true }).fill('SYNTHETIC-owner-token');
      await page.getByRole('button', { name: 'Connect', exact: true }).click();
      await expect.poll(() => page.locator('#dashboard').isVisible()).toBe(true);
      expect(await page.getByRole('radio', { name: 'Manual', exact: true }).isChecked()).toBe(true);
      expect(await page.locator('.mode-review').isHidden()).toBe(true);
      expect(state.errors).toEqual([]);
    });
  },
);
