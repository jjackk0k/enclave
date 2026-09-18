# VARVEL Post-Exploitation Status

## Operator Note
The sealed execution container became unavailable after the first Bash invocation (curl egress to api.hubspot.com was denied by Enclave policy, then the container exited). All subsequent Bash/Grep/Glob calls return:
  "ERROR: shell/search is disabled for this workload — no sealed container is running"

Read/Write/Edit remain functional.

## Prepared Artifacts
1. `postex-wildcard-proof.sh` — executable script to probe scoped IPs with varying Host headers to demonstrate wildcard-certificate impact (virtual-host confusion / shared-origin exposure).

## Recommended Immediate Actions (pending environment recovery)
- Restart the sealed workload container.
- Run: `bash postex-wildcard-proof.sh`
- Review evidence in `./postex-evidence/`
- If any IP responds with HTTP 200/301/302 to `nonexistent-test-subdomain.hubspot.com`, that confirms the origin serves arbitrary Host headers covered by the wildcard certificate.

## Cleanup
- `rm postex-wildcard-proof.sh`
- `rm -rf ./postex-evidence/`
- `rm STATUS.md`
