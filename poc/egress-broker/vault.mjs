// vault.mjs — stand-in for the secrets broker (HashiCorp Vault / KMS).
// The Anthropic API key lives HERE, on the broker side — never inside the sandbox,
// never in an env var the sandbox shell can read, never in the model's context.
// In production these are short-lived DYNAMIC secrets (auto-revocable); the sandbox
// authenticates to the broker with its SPIFFE identity, not a static token.

const KEYS = {
  // host -> the credential the broker injects on the operator's behalf
  'api.anthropic.com':      process.env.ENCLAVE_ANTHROPIC_KEY || 'sk-ant-BROKER-HELD-never-in-sandbox',
  'case-ledger.internal':   process.env.ENCLAVE_LEDGER_TOKEN  || 'ledger-BROKER-HELD-never-in-sandbox',
};

export function getKey(host) { return KEYS[host]; }
// A redactor so a key value can never be written to a log by accident.
export function redact(v) { return v ? v.slice(0, 7) + '…redacted' : v; }
