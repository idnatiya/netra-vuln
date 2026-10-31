# sfgw-production — triage 2026-10-31

## Coverage and limitations

Read-only SSH through `sfgw-prod` confirmed hostname `sfgw-production`, Ubuntu 24.04.2 and running kernel 6.8.0-137-generic. MCP access recovered and all 2,098 findings were read (392 unique CVEs); advisory/runtime triage remains partial. No production workload changes were made.

## Applied verdicts

With explicit owner approval, 24 findings were individually changed to `false_positive` through MCP, with platform evidence, advisory links and re-evaluation conditions. Read-back verified all 24 statuses and notes. Remaining open totals: 105 critical and 1,969 high; false_positive total: 24. These totals reflect triage, not a new scan or package remediation.

- CVE-2024-51736 (Windows-only Symfony Process issue): ID 2706.
- CVE-2026-39836 (Windows-only Go net panic; https://pkg.go.dev/vuln/GO-2026-4971): IDs 2037, 2066, 2096, 2122, 2153, 2182, 2212, 2238, 2285, 2731, 2762, 2793, 2824, 2857, 2886, 2916, 2942, 2968, 2999, 3028, 3058, 3084, 3110.

The proposal and next-step sections below retain the original investigation context; the two CVEs listed above have now been applied, and complete inventory retrieval is no longer blocked.

## Proposed verdicts

| Finding selector (host 2) | Proposed status | Evidence and priority | Re-evaluate when |
|---|---|---|---|
| CVE-2024-51736, symfony/process v6.4.4, /var/www/api | false_positive | Official Symfony advisory requires Windows cmd.exe resolution; SSH confirms Ubuntu. Version match is real, but this exploit is not applicable to this host. Retrieve exact finding ID before applying. | Workload is deployed to Windows or platform evidence changes. |
| CVE-2024-34344, nuxt 3.8.1, both sales folders | open | Official advisory concerns local e2e test server and malicious browser interaction. Observed sales processes run .output/server/index.mjs; no named Vitest/Nuxt test process observed. Lower immediate runtime priority provisionally; a process snapshot does not rule out scheduled tests. | Tests/dev server run here, deployment changes, or vulnerable test routes are found. |
| DevTools, Vitest, tinypool, Babel and esbuild findings in app/build trees | open | No named test/build process observed in the snapshot. This does not prove dependencies are unused, absent from builds or unreachable through application code. Require package-specific advisory review and build/scheduler verification before any suppression. | Build/test execution or untrusted build inputs are identified. |
| Kernel findings for 6.8.0-137 | open | This is the running kernel. /boot also contains 6.8.0-147-generic and reboot-required exists. Do not dismiss headers/tools rows as false positives while the corresponding vulnerable kernel runs. 35 critical rows represent seven CVEs across five packages in the earlier scan. | After approved reboot, verify active version, installed packages and rescan. |
| PhpSpreadsheet findings, /var/www/api | open | Nginx enabled old-api config references /var/www/api/public and PHP 8.1 FPM. ProductNewJob and ProductUpdatePriceJob call Excel::import with local files. Reachability and attacker control need tracing; importing local files alone does not establish SSRF/RCE or eliminate risk. | Input validation and full upload-to-import flow are reviewed or dependency is upgraded. |
| Any finding under /home/dev/project/sales | open | Four running Node workers use that folder's .output/server/index.mjs. Enabled dev-sales Nginx config proxies to port 5000. Folder naming is not evidence of inactivity. | Deployment is removed and a new scan confirms remediation. |
| Any finding under /var/www/frontend or /var/www/api | open | Enabled old-app and old-api Nginx configs still reference these paths. Do not assume old copies are unused. Config files alone do not establish loaded Nginx configuration or external reachability. | Effective configuration and request routing are verified. |

No `accepted` verdict is proposed: no explicit risk acceptance from an owner exists. Do not apply a component-wide false_positive verdict based on the single Windows-specific CVE.

## Supporting runtime evidence

- Both /var/www/sales/.output/server/index.mjs and /home/dev/project/sales/.output/server/index.mjs have running workers.
- Enabled Nginx api config references /var/www/optimized/public; app references /var/www/optimized-frontend/dist. Optimized Laravel queue workers are running.
- Relevant loaded-module snapshot shows kvm and kvm_amd; no matches for nfsd, nvmet, sctp, rdma, siw or srpt. Module absence alone is insufficient for false_positive because of built-in support or autoloading.
- Multiple services bind wildcard addresses. Firewall rules and external access were not checked; wildcard binding does not prove internet exposure.

## Next steps to finish inventory-wide triage

1. Once Netra rate limiting clears, retrieve all unresolved critical/high pages with conservative pacing, stopping on errors. Record IDs and scan timestamp; verify complete page counts.
2. Join findings by exact CVE/package/component/version. Review all platform-specific advisories and assess build/test dependency call paths and automation individually.
3. Trace upload controllers to import jobs; inspect effective Nginx config, runtime package versions and dev/test routes without invoking application code or exploits.
4. Produce per-ID proposed notes/statuses. Apply only the Windows-specific verdict once identity is verified and status changes are authorized; retain uncertain findings as open.

## Sources

- https://symfony.com/blog/cve-2024-51736-command-execution-hijack-on-windows-with-process-class
- https://github.com/nuxt/nuxt/security/advisories/GHSA-v784-fjjh-f8r4

The official Nuxt advisory rates CVE-2024-34344 High (8.8), whereas the earlier scanner result labeled it Critical. Preserve scanner evidence and note the discrepancy; do not infer exploitability from severity alone.
