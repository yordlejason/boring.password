import { isDeepStrictEqual } from 'node:util';
import { chromium, type Browser, type BrowserContext, type Page } from 'playwright';
import {
  createSyntheticManifest,
  type SyntheticManifest,
} from '../../adapters/synthetic-login/manifest.js';
import { SyntheticSecretService, type TrustedSecretChannel } from '../secret-service/index.js';
import {
  TrustedOperationError,
  type BrokerPort,
  type ExecutionBinding,
  type WorkerBinding,
  type WorkerFailureCode,
} from './contracts.js';

export type AuthenticationResult =
  | { state: 'SUCCEEDED'; sessionRef: string }
  | { state: 'FAILED' | 'OUTCOME_UNKNOWN'; code: WorkerFailureCode };

export interface SyntheticProfile {
  accountRef: 'acct_synthetic';
  displayName: 'Synthetic Owner';
  service: 'Synthetic Login';
  permission: 'read_profile';
}

interface ProtectedPage {
  context: BrowserContext;
  page: Page;
  unexpectedNavigation: boolean;
  unexpectedFlow: boolean;
}

/**
 * Trusted-only adapter runtime. Deliberately has no page, cookie, screenshot, CDP,
 * script, storage, selector, URL-navigation, HAR, or tracing endpoint.
 */
export class SyntheticBrowserWorker {
  readonly #broker: BrokerPort;
  readonly #manifest: SyntheticManifest;
  readonly #identity: Readonly<WorkerBinding>;
  readonly #secretService: SyntheticSecretService;
  readonly #sessions = new Map<string, ProtectedPage>();
  #browser: Browser | undefined;
  #runtimeBusy = false;
  #quarantined = false;

  constructor(options: {
    broker: BrokerPort;
    origin: string;
    workerId: string;
    runtimeId: string;
    runtimeGeneration: number;
    secretService?: SyntheticSecretService;
  }) {
    this.#broker = options.broker;
    this.#manifest = createSyntheticManifest(options.origin);
    this.#identity = Object.freeze({
      workerId: options.workerId,
      runtimeId: options.runtimeId,
      runtimeGeneration: options.runtimeGeneration,
    });
    this.#secretService = options.secretService ?? new SyntheticSecretService(options.broker);
  }

  async authenticate(requestId: string): Promise<AuthenticationResult> {
    if (this.#quarantined) return { state: 'OUTCOME_UNKNOWN', code: 'OUTCOME_UNKNOWN' };
    if (this.#runtimeBusy) return { state: 'FAILED', code: 'POLICY_DENIED' };
    this.#runtimeBusy = true;
    let binding: ExecutionBinding | undefined;
    let protectedPage: ProtectedPage | undefined;
    let possibleDelivery = false;
    try {
      binding = await this.#broker.acquireExecution(requestId, this.#identity);
      this.#validateBinding(binding);
      protectedPage = await this.#newPage();
      const activeBinding = binding;
      const activePage = protectedPage;
      const channel: TrustedSecretChannel = this.#secretService.connectTrustedWorker({
        injectPassword: async (value) => {
          await this.#inject(activePage, activeBinding, 'password', value);
          await this.#broker.recordSecretDelivered(activeBinding.attemptId, 'password');
        },
        injectTotp: async (value) => {
          await this.#inject(activePage, activeBinding, 'totp', value);
          await this.#broker.recordSecretDelivered(activeBinding.attemptId, 'totp');
        },
      });
      await activePage.page.goto(`${this.#manifest.origin}${this.#manifest.paths.password}`, {
        waitUntil: 'domcontentloaded',
      });
      await this.#assertStep(activePage, 'password');
      const passwordPermit = await this.#broker.issuePermit(
        binding.attemptId,
        'password',
        'enter_password',
      );
      // Conservative from this point: consumption/delivery could race an exception.
      possibleDelivery = true;
      await channel.consumePasswordPermit(passwordPermit.permitId, binding);
      await this.#submit(activePage, 'password');
      await this.#assertStep(activePage, 'totp');
      const totpPermit = await this.#broker.issuePermit(binding.attemptId, 'totp', 'enter_totp');
      await channel.consumeTotpPermit(totpPermit.permitId, binding);
      await this.#submit(activePage, 'totp');
      await this.#verifyAuthenticated(activePage);
      const result = await this.#broker.completeExecution(binding.attemptId, {
        verifiedAccountId: this.#manifest.accountId,
      });
      this.#sessions.set(result.sessionRef, activePage);
      protectedPage = undefined;
      return { state: 'SUCCEEDED', sessionRef: result.sessionRef };
    } catch (error) {
      const code =
        error instanceof TrustedOperationError
          ? error.code
          : protectedPage?.unexpectedNavigation
            ? 'DESTINATION_MISMATCH'
            : protectedPage?.unexpectedFlow
              ? 'INTERACTION_REQUIRED'
              : possibleDelivery
                ? 'OUTCOME_UNKNOWN'
                : 'AUTH_FAILED';
      if (code === 'OUTCOME_UNKNOWN') this.#quarantined = true;
      if (binding) {
        try {
          await this.#broker.crashExecution(binding.attemptId, code);
        } catch {
          /* no raw exceptions escape */
        }
      }
      return { state: code === 'OUTCOME_UNKNOWN' ? 'OUTCOME_UNKNOWN' : 'FAILED', code };
    } finally {
      if (protectedPage) await protectedPage.context.close().catch(() => undefined);
      this.#runtimeBusy = false;
    }
  }

  async readProfile(sessionRef: string): Promise<SyntheticProfile> {
    const session = this.#sessions.get(sessionRef);
    if (!session) throw new TrustedOperationError('POLICY_DENIED');
    try {
      await this.#verifyAuthenticated(session);
      // Observation gateway creates a new allowlisted object. No page text is copied.
      return {
        accountRef: 'acct_synthetic',
        displayName: 'Synthetic Owner',
        service: 'Synthetic Login',
        permission: 'read_profile',
      };
    } catch (error) {
      await this.endSession(sessionRef);
      if (error instanceof TrustedOperationError) throw error;
      throw new TrustedOperationError('AUTH_FAILED');
    }
  }

  async endSession(sessionRef: string): Promise<void> {
    const session = this.#sessions.get(sessionRef);
    this.#sessions.delete(sessionRef);
    if (session) await session.context.close().catch(() => undefined);
  }

  async close(): Promise<void> {
    for (const sessionRef of this.#sessions.keys()) await this.endSession(sessionRef);
    const browser = this.#browser;
    this.#browser = undefined;
    if (browser) await browser.close().catch(() => undefined);
  }

  #validateBinding(binding: ExecutionBinding): void {
    if (
      binding.workerId !== this.#identity.workerId ||
      binding.runtimeId !== this.#identity.runtimeId ||
      binding.runtimeGeneration !== this.#identity.runtimeGeneration ||
      binding.destination !== this.#manifest.origin ||
      binding.identityProvider !== this.#manifest.origin ||
      binding.relyingParty !== this.#manifest.origin
    ) {
      throw new TrustedOperationError('DESTINATION_MISMATCH');
    }
    if (binding.accountId !== this.#manifest.accountId)
      throw new TrustedOperationError('ACCOUNT_MISMATCH');
    if (
      binding.adapterId !== this.#manifest.id ||
      binding.adapterVersion !== this.#manifest.version ||
      binding.sessionActionProfile !== this.#manifest.actionProfile ||
      binding.credentialBindingVersion !== 1 ||
      binding.observationProfile !== this.#manifest.actionProfile ||
      !isDeepStrictEqual(binding.factors, ['password', 'totp']) ||
      // JSONB can reorder object keys. Compare exact structure and values while
      // preserving the reviewed factor/step array order and rejecting extra keys.
      !isDeepStrictEqual(binding.factorPlan, [
        { factor: 'password', step: 'enter_password' },
        { factor: 'totp', step: 'enter_totp' },
      ])
    ) {
      throw new TrustedOperationError('ADAPTER_UNSUPPORTED');
    }
  }

  async #newPage(): Promise<ProtectedPage> {
    if (!this.#browser)
      this.#browser = await chromium.launch({ headless: true, chromiumSandbox: true });
    const context = await this.#browser.newContext({
      serviceWorkers: 'block',
      acceptDownloads: false,
    });
    const page = await context.newPage();
    page.setDefaultTimeout(5000);
    page.setDefaultNavigationTimeout(5000);
    const protectedPage: ProtectedPage = {
      context,
      page,
      unexpectedNavigation: false,
      unexpectedFlow: false,
    };
    // Block non-reviewed destinations, embedded frames, redirects and resource loads.
    await context.route('**/*', async (route) => {
      const request = route.request();
      let destination: URL;
      try {
        destination = new URL(request.url());
      } catch {
        protectedPage.unexpectedNavigation = true;
        await route.abort();
        return;
      }
      if (
        destination.origin !== this.#manifest.origin ||
        (request.isNavigationRequest() && request.frame() !== page.mainFrame())
      ) {
        protectedPage.unexpectedNavigation = true;
        await route.abort();
      } else if (
        !(Object.values(this.#manifest.paths) as string[]).includes(destination.pathname) ||
        destination.search ||
        destination.hash
      ) {
        if (destination.pathname !== '/favicon.ico') protectedPage.unexpectedFlow = true;
        await route.abort();
      } else await route.continue();
    });
    page.on('download', () => {
      protectedPage.unexpectedNavigation = true;
    });
    context.on('page', (newPage) => {
      if (newPage !== page) {
        protectedPage.unexpectedNavigation = true;
        void newPage.close().catch(() => undefined);
      }
    });
    return protectedPage;
  }

  #assertOrigin(active: ProtectedPage, expectedPath: string): void {
    let top: URL;
    try {
      top = new URL(active.page.url());
    } catch {
      throw new TrustedOperationError('DESTINATION_MISMATCH');
    }
    if (
      active.unexpectedNavigation ||
      top.origin !== this.#manifest.origin ||
      active.page.mainFrame().url() !== top.href ||
      active.page.frames().length !== 1 ||
      top.search ||
      top.hash
    ) {
      throw new TrustedOperationError('DESTINATION_MISMATCH');
    }
    if (active.unexpectedFlow) throw new TrustedOperationError('INTERACTION_REQUIRED');
    if (top.pathname !== expectedPath) throw new TrustedOperationError('INTERACTION_REQUIRED');
  }

  async #assertStep(active: ProtectedPage, step: 'password' | 'totp'): Promise<void> {
    this.#assertOrigin(active, this.#manifest.paths[step]);
    const state = await active.page.evaluate(
      ({ expectedStep, account, username, action }) => {
        const form = document.querySelector(
          `#${expectedStep === 'password' ? 'login' : 'totp'}-form`,
        );
        const input = document.querySelector(
          `#${expectedStep === 'password' ? 'password' : 'totp'}`,
        );
        return {
          step: form?.getAttribute('data-auth-step') === expectedStep,
          account: form ? form.getAttribute('data-account') === account : undefined,
          input: input instanceof HTMLInputElement && input.form === form,
          action:
            form instanceof HTMLFormElement && form.action === action && form.method === 'post',
          type:
            input instanceof HTMLInputElement &&
            input.type === (expectedStep === 'password' ? 'password' : 'text'),
          username:
            expectedStep !== 'password' ||
            (document.querySelector('#username') as HTMLInputElement | null)?.value === username,
          interaction: Boolean(document.querySelector('[data-interaction],iframe')),
        };
      },
      {
        expectedStep: step,
        account: this.#manifest.accountId,
        username: this.#manifest.username,
        action: `${this.#manifest.origin}${step === 'password' ? this.#manifest.paths.passwordSubmit : this.#manifest.paths.totpSubmit}`,
      },
    );
    this.#assertOrigin(active, this.#manifest.paths[step]);
    if (state.account === false) throw new TrustedOperationError('ACCOUNT_MISMATCH');
    if (
      !state.step ||
      !state.input ||
      !state.action ||
      !state.type ||
      !state.username ||
      state.interaction
    )
      throw new TrustedOperationError('INTERACTION_REQUIRED');
  }

  async #inject(
    active: ProtectedPage,
    binding: ExecutionBinding,
    step: 'password' | 'totp',
    value: string,
  ): Promise<void> {
    this.#validateBinding(binding);
    await this.#assertStep(active, step);
    this.#assertOrigin(active, this.#manifest.paths[step]);
    // One synchronous DOM operation validates frame, top origin, route, account,
    // step and field immediately before insertion. No agent script runs here.
    const inserted = await active.page.mainFrame().evaluate(
      ({ origin, path, action, account, username, expectedStep, secret }) => {
        if (
          window !== window.top ||
          location.origin !== origin ||
          location.pathname !== path ||
          location.search ||
          location.hash
        )
          return false;
        const form = document.querySelector(
          `#${expectedStep === 'password' ? 'login' : 'totp'}-form`,
        );
        const input = document.querySelector(
          `#${expectedStep === 'password' ? 'password' : 'totp'}`,
        );
        if (
          !(form instanceof HTMLFormElement) ||
          !(input instanceof HTMLInputElement) ||
          input.form !== form ||
          form.dataset.authStep !== expectedStep ||
          form.dataset.account !== account ||
          document.querySelector('[data-interaction],iframe') ||
          form.action !== action ||
          form.method !== 'post' ||
          input.type !== (expectedStep === 'password' ? 'password' : 'text') ||
          (expectedStep === 'password' &&
            (document.querySelector('#username') as HTMLInputElement | null)?.value !== username)
        )
          return false;
        input.value = secret;
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
        return true;
      },
      {
        origin: this.#manifest.origin,
        path: this.#manifest.paths[step],
        account: this.#manifest.accountId,
        action: `${this.#manifest.origin}${step === 'password' ? this.#manifest.paths.passwordSubmit : this.#manifest.paths.totpSubmit}`,
        username: this.#manifest.username,
        expectedStep: step,
        secret: value,
      },
    );
    if (!inserted) throw new TrustedOperationError('INTERACTION_REQUIRED');
  }

  async #submit(active: ProtectedPage, step: 'password' | 'totp'): Promise<void> {
    await this.#assertStep(active, step);
    try {
      await Promise.all([
        active.page.waitForURL(
          `${this.#manifest.origin}${step === 'password' ? '/totp' : '/profile'}`,
          { waitUntil: 'domcontentloaded' },
        ),
        active.page
          .evaluate(
            ({ origin, path, action, expectedStep, account }) => {
              const form = document.querySelector(
                `#${expectedStep === 'password' ? 'login' : 'totp'}-form`,
              );
              const button = document.querySelector(
                `#${expectedStep === 'password' ? 'password' : 'totp'}-submit`,
              );
              if (
                window !== window.top ||
                location.origin !== origin ||
                location.pathname !== path ||
                location.search ||
                location.hash ||
                !(form instanceof HTMLFormElement) ||
                !(button instanceof HTMLButtonElement) ||
                button.form !== form ||
                form.action !== action ||
                form.method !== 'post' ||
                form.dataset.account !== account ||
                form.dataset.authStep !== expectedStep ||
                document.querySelector('[data-interaction],iframe')
              )
                return false;
              form.requestSubmit(button);
              return true;
            },
            {
              origin: this.#manifest.origin,
              path: this.#manifest.paths[step],
              expectedStep: step,
              account: this.#manifest.accountId,
              action: `${this.#manifest.origin}${step === 'password' ? this.#manifest.paths.passwordSubmit : this.#manifest.paths.totpSubmit}`,
            },
          )
          .then((submitted) => {
            if (!submitted) throw new TrustedOperationError('INTERACTION_REQUIRED');
          }),
      ]);
    } catch {
      // A known changed flow is a typed refusal. Lost/ambiguous submissions are
      // conservatively OUTCOME_UNKNOWN, and never retried by this adapter.
      const expected = step === 'password' ? '/totp' : '/profile';
      this.#assertOrigin(active, expected);
      throw new TrustedOperationError('OUTCOME_UNKNOWN');
    }
  }

  async #verifyAuthenticated(active: ProtectedPage): Promise<void> {
    this.#assertOrigin(active, this.#manifest.paths.authenticated);
    const state = await active.page.evaluate(() => {
      const profile = document.querySelector('#profile');
      return {
        account: profile?.getAttribute('data-account'),
        authenticated: profile?.getAttribute('data-authenticated') === 'true',
        unsupported: Boolean(
          document.querySelector('form,input[type="password"],[data-interaction],iframe'),
        ),
      };
    });
    this.#assertOrigin(active, this.#manifest.paths.authenticated);
    if (state.account !== this.#manifest.accountId)
      throw new TrustedOperationError('ACCOUNT_MISMATCH');
    if (!state.authenticated || state.unsupported)
      throw new TrustedOperationError('INTERACTION_REQUIRED');
  }
}
