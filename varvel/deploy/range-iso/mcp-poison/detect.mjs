// range-iso mcp-poison lab — detector compat shim.
// GRADUATED: the detectors built and calibrated here were pinned into the real MCP
// client path as engine/mcpguard.mjs (research-lane graduation, 2026-08-29 — see
// docs/research/mcp-poison-lab-2026-08-29.md). This file re-exports them so the lab
// harness/tests and the production client share ONE implementation: if the pinned
// control drifts, the lab that calibrated it drifts with it, visibly.

export {
  INSTRUCTION_PATTERNS,
  scanText,
  scanToolDescriptions,
  scanToolOutput,
  SchemaDriftWatcher,
  McpScreen,
  SCREEN_POLICY,
} from '../../../engine/mcpguard.mjs';
