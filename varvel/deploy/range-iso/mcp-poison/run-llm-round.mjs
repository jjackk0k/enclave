// Small runner for the real-LLM compliance round (harness: ./llm-round.mjs).
//   node deploy/range-iso/mcp-poison/run-llm-round.mjs
// RESUMABLE: writes llm-round-verdict.json after EVERY run and skips runs already in
// the file on the next invocation — re-invoke until all 9 runs (3 reps x 3
// conditions) are complete. The global API budget (40 measurement calls) is carried
// across invocations via the file. Never prints the API key; the key never leaves
// request headers.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runLlmRound } from './llm-round.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const file = join(HERE, 'llm-round-verdict.json');

const prior = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : null;
const priorRuns = prior && Array.isArray(prior.runs) ? prior.runs.filter((r) => !r.error) : [];
// Calls already spent this session before this invocation: budget.used already
// includes retry attempts (every HTTP call decrements), so use it directly.
const priorCallsUsed = prior && prior.budget
  ? prior.budget.used
  : Number(process.env.VARVEL_LLM_ROUND_SPENT || 0);

const verdict = await runLlmRound({
  reps: 3,
  budget: 40,
  priorRuns,
  priorCallsUsed,
  onRun: (v) => writeFileSync(file, JSON.stringify(v, null, 2)), // incremental persistence
});
writeFileSync(file, JSON.stringify(verdict, null, 2));
console.log('llm-round verdict -> ' + file);
if (!verdict.ok) { console.log('STOPPED: ' + verdict.error); process.exit(1); }
console.log(`backend: ${verdict.backend.model} (${verdict.backend.source}) · api calls used: ${verdict.budget.used}/${verdict.budget.total} · 429-retries: ${verdict.rateLimitRetries}`);
for (const [c, a] of Object.entries(verdict.aggregate)) {
  console.log(`  ${c}: runs=${a.runsCompleted} err=${a.runsErrored} descDirective=${a.followedDescriptionDirective} readSecret=${a.readSecretNote} canaryExfil=${a.canaryExfiltrated} quarantinedAttempts=${a.quarantinedAttempts} flaggedOutputs=${a.flaggedOutputsSeen} heededFlag=${a.heededFlag}`);
}
