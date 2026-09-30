-- Metadata only. No passwords, seeds, codes, cookies, tokens or browser state.
CREATE TABLE IF NOT EXISTS broker_metadata (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  boot_epoch text,
  quarantined_runtimes jsonb NOT NULL DEFAULT '{}'::jsonb
);
INSERT INTO broker_metadata(singleton) VALUES (true) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS auth_requests (
  id text PRIMARY KEY, owner_id text NOT NULL, client_id text NOT NULL,
  idempotency_key text NOT NULL, revision integer NOT NULL CHECK (revision > 0),
  state text NOT NULL, body jsonb NOT NULL,
  UNIQUE(owner_id, client_id, idempotency_key)
);
CREATE TABLE IF NOT EXISTS approval_challenges (
  id text PRIMARY KEY, request_id text NOT NULL REFERENCES auth_requests(id),
  request_revision integer NOT NULL, device_id text NOT NULL, nonce text NOT NULL UNIQUE,
  payload_bytes bytea NOT NULL, payload_digest text NOT NULL, consumed_at timestamptz,
  body jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS execution_attempts (
  id text PRIMARY KEY, request_id text NOT NULL REFERENCES auth_requests(id),
  request_revision integer NOT NULL, execution_generation integer NOT NULL,
  runtime_id text NOT NULL, state text NOT NULL, lease_expires_at timestamptz NOT NULL,
  body jsonb NOT NULL, UNIQUE(request_id, request_revision, execution_generation)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_runtime_attempt
  ON execution_attempts(runtime_id) WHERE state = 'ACTIVE';
CREATE TABLE IF NOT EXISTS secret_permits (
  id text PRIMARY KEY, request_id text NOT NULL REFERENCES auth_requests(id),
  request_revision integer NOT NULL, attempt_id text NOT NULL REFERENCES execution_attempts(id),
  factor text NOT NULL CHECK(factor IN ('password','totp')), adapter_step text NOT NULL,
  consumed_at timestamptz, body jsonb NOT NULL,
  UNIQUE(attempt_id, factor, adapter_step)
);
CREATE TABLE IF NOT EXISTS secret_permit_consumptions (
  permit_id text PRIMARY KEY REFERENCES secret_permits(id), consumed_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS protected_sessions (
  id text PRIMARY KEY, request_id text NOT NULL REFERENCES auth_requests(id),
  owner_id text NOT NULL, client_id text NOT NULL, workload_id text NOT NULL, body jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  id text PRIMARY KEY, event text NOT NULL, timestamp timestamptz NOT NULL, body jsonb NOT NULL
);
