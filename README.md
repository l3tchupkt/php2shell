# PHP2Shell Research Lab

A research repository for examining the reported PHP2Shell vulnerabilities and evaluating defensive controls in an isolated, intentionally vulnerable PHP environment.

> **Safety notice:** Use this lab only on systems you own or have explicit written permission to test. Do not expose the vulnerable container to the public internet. This repository is for controlled security research and defensive validation; it is not a production deployment.

## Scope

This repository contains a Docker-based test environment and supporting files for studying:

- PHP multipart request and session upload-progress behavior.
- The security impact of running unpatched PHP versions.
- Detection opportunities in application, web-server, and process telemetry.
- Patch verification and defensive configuration.

CVE identifiers, affected-version ranges, severity scores, and exploit claims should be treated as **unverified until checked against official PHP security advisories**. Do not use this README as the sole source for vulnerability or remediation decisions.

## Repository layout

- `Dockerfile`, `docker-compose.yml` — containerized lab setup.
- `php.ini`, `nginx.conf`, `supervisord.conf` — lab service configuration.
- `www/` — deliberately vulnerable test application.
- `scripts/verify.sh` — lab verification helper.
- `exploit/` — proof-of-concept research files; inspect the code before running anything.

## Safe handling

1. Run the lab only in a disposable local environment.
2. Keep the container bound to localhost or an isolated network; do not publish it to the internet.
3. Do not test third-party hosts or bulk-scan targets without explicit authorization.
4. Avoid mounting host directories, Docker sockets, SSH keys, credentials, or other sensitive files into the lab.
5. Prefer patched PHP builds for any non-research workload.
6. Tear down the lab when finished and review container logs for unexpected behavior.

## Defensive validation

- Inventory PHP versions across your systems.
- Compare installed versions with the official PHP security release notes.
- Upgrade to a vendor-supported fixed release; configuration changes are not a substitute for patching.
- Review web-server and PHP-FPM logs for unusual multipart request patterns, repeated worker crashes, and unexpected child-process execution.
- Validate fixes in a controlled staging environment before production rollout.

## References

- [Official PHP website](https://www.php.net/)
- [PHP supported versions](https://www.php.net/supported-versions.php)
- [PHP security announcements](https://www.php.net/archive/)
- [Original upstream project: wakemeiflose/php2shell](https://github.com/wakemeiflose/php2shell)

This repository is a derivative research copy. Preserve applicable upstream attribution, license notices, and any notices required by the original license. Changes made in this repository should be documented separately from upstream work.

## License

See [LICENSE](LICENSE) for the applicable license terms.
