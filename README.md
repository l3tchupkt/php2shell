# PHP2Shell Research Lab

A Docker-based PHP security research lab for studying multipart uploads, session upload-progress behavior, and defensive validation in an intentionally vulnerable local application.

**Keywords:** PHP security, security research, vulnerability analysis, Docker, multipart/form-data, session upload progress, memory safety, defensive testing, penetration testing lab.

> **Authorized use only.** Use this project only in a disposable environment you own or are explicitly authorized to test. Do not expose the vulnerable service to the public internet. Review all code before running it.

## What's included

- `Dockerfile`, `docker-compose.yml` — containerized lab setup.
- `php.ini`, `nginx.conf`, `supervisord.conf` — lab configuration.
- `www/` — intentionally vulnerable test application.
- `scripts/verify.sh` — local lab verification helper.
- `exploit/` — Python security-research scripts and dependency list.

## Requirements

- Docker Engine or Docker Desktop with Compose support.
- Python 3.10+ for inspecting and working with the research scripts.
- A disposable environment. Do not mount host credentials, sensitive directories, or the Docker socket into the lab.

## Start the local lab

Clone the repository:

```bash
git clone https://github.com/l3tchupkt/php2shell.git
cd php2shell
```

Review `docker-compose.yml` and the service configuration before starting anything. Confirm the vulnerable service is bound to localhost or an isolated network and is not publicly accessible.

Build and start the lab:

```bash
docker compose up --build -d
docker compose ps
```

## Verify the setup

Run the included verification helper:

```bash
bash scripts/verify.sh
```

To inspect the Python scripts' supported options without launching a test, use their help output:

```bash
python3 exploit/php2shell.py --help
python3 exploit/uaf_probe.py --help
```

For local development, create a virtual environment before installing the listed dependencies:

```bash
python3 -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
# .venv\\Scripts\\Activate.ps1
python -m pip install -r exploit/requirements.txt
```

Only perform active testing against a lab instance you control or a target covered by explicit written authorization. Do not use these scripts for bulk scanning or against public/third-party systems without a clearly defined, authorized scope. Review the code and its network behavior before execution.

## Stop the lab

When finished:

```bash
docker compose down
```

Review container logs and remove disposable test data as appropriate.

## Defensive guidance

- Confirm affected and fixed versions using official PHP security advisories.
- Upgrade to a supported, patched PHP release; configuration changes are not a substitute for patching.
- Review web-server and PHP-FPM logs for unusual multipart requests, repeated worker crashes, and unexpected child-process execution.
- Validate fixes in an isolated staging environment before production rollout.

## References

- [PHP official website](https://www.php.net/)
- [PHP supported versions](https://www.php.net/supported-versions.php)
- [PHP security announcements](https://www.php.net/archive/)
- [Related upstream research repository](https://github.com/wakemeiflose/php2shell)

Verify vulnerability identifiers, affected-version ranges, and exploitability claims against authoritative advisories before relying on them.
