# Security Automation

Unified security scanning utility that executes multiple security tools and returns a combined result.

## Tools

- Semgrep (SAST)
- Pip-Audit (Dependency Scanning)
- Gitleaks (Secrets Detection)
- Checkov (IaC Scanning)

## Usage

```bash
python security-scan.py --path ./app --format json
```

## Example

```bash
python security-scan.py --path ./tests/vulnerable-app --format json
```

## Exit Codes

| Code | Meaning |
|--------|--------|
| 0 | PASS |
| 1 | FAIL or ERROR |

## Prerequisites

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Install Gitleaks separately.

Verify:

```bash
gitleaks version
```