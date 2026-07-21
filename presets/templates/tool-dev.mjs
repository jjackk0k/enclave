// Preset: Security Tool Development (incl. red-team tooling)
export default {
  id: 'tool-dev',
  title: 'Security Tool Development',
  workload: 'tool-dev',
  // Building security/offensive tooling is senior work: L4 + an offensive / exploit-dev cert.
  requires: { clearance: 4, anyCert: ['OSCP', 'OSEP', 'OSED', 'OSWE', 'CRTO', 'GXPN'] },
  // Dev workspaces need controlled package-registry access — allowlisted, through the proxy.
  egress: { default: 'deny', allow: [
    'api.anthropic.com', 'case-ledger.internal',
    'proxy.golang.org', 'sum.golang.org', 'registry.npmjs.org',
    'pypi.org', 'files.pythonhosted.org', 'static.crates.io', 'github.com',
  ] },
  // Curated best-in-class toolchain (see /tool-shelf.mjs for the full gated shelf).
  tools: ['clang+gcc (ASan/UBSan)', 'mingw-w64', 'zig', 'rust+cross', 'go', 'dotnet', 'qemu', 'gdb+pwndbg', 'ghidra', 'afl++', 'pwntools'],
  params: [
    { key: 'tool',     prompt: 'Tool name', required: true },
    { key: 'platform', prompt: 'Target platform (linux / windows / both)', default: 'both' },
    { key: 'purpose',  prompt: 'Purpose / what it does', required: true },
    { key: 'lead',     prompt: 'Lead developer', required: true },
  ],
  docs: {
    'TOOL-SPEC.md':
`# Tool Spec — {{tool}}

**Lead:** {{lead}}
**Target platform(s):** {{platform}}
**Generated:** {{date}}

## Purpose
{{purpose}}

## Design
- Inputs / outputs:
- Key behaviours:
- Dependencies (must be from the allowlisted registries):

## Authorization note
This is built inside a sealed enclave. Building the tool is gated to L4 + an offensive/
exploit-dev certification. **Using** the finished tool against a target is separately
gated at runtime — offensive actions require the operator's cert AND an in-scope,
signed target — so a tool built here still can't be pointed off-scope.
`,
    'BUILD-AND-TEST.md':
`# Build & Test — {{tool}}

The enclave is Linux-based, so:
- **Linux target:** build natively (\`go build\`, \`cargo build\`, \`make\`).
- **Windows target:** cross-compile — e.g. \`GOOS=windows GOARCH=amd64 go build\`,
  or mingw-w64 for C/C++. (Run/test Windows binaries in the Windows isolation tier.)

## Steps
1. Scaffold the project; pin dependencies from the allowlisted registries.
2. Build for each target platform; keep builds reproducible.
3. Test against the AUTHORISED, in-scope test target only — never off-scope.
4. Record artefacts + hashes; findings and binaries stay in the enclave.
`,
    'RULES.md':
`# Handling Rules — {{tool}}

- Tooling and any test artefacts stay inside the enclave; export is a logged, approved action.
- Test only against authorised, in-scope targets (enforced by the egress firewall).
- No production/destructive testing without written sign-off.
- Every build, run, and file touch is written to the immutable ledger.
`,
  },
};
