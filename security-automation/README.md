# Security Automation

A Python-based security orchestration utility that executes multiple security scans and aggregates the results into a unified report.

## Supported Scanners

| Scanner | Purpose |
|----------|----------|
| Semgrep | SAST |
| Pip-Audit | Dependency Vulnerability Scanning |
| Gitleaks | Secret Detection |
| Checkov | Infrastructure as Code Scanning |

## Example

```bash
python security-scan.py \
    --path ./tests/insecure-terraform \
    --format json
```

## Output

```json
{
  "summary": {
    "overall_status": "FAIL"
  }
}
```

## Exit Codes

| Code | Description |
|---------|------------|
| 0 | PASS |
| 1 | FAIL / Vulnerabilities Found |


## Example Results

### Terraform Scan

```json
{
  "summary": {
    "overall_status": "FAIL",
    "pass": 2,
    "fail": 1,
    "error": 0
  }
}
```

Detected:

- Open SSH access from 0.0.0.0/0
- Missing security group descriptions
- Detached security group

### Security Scanner Enhancements

Implemented a significantly improved security automation workflow:

- Added structured JSON parsing for Semgrep, Checkov, Gitleaks and pip-audit
- Added vulnerability deduplication
- Added severity classification
- Added risk score calculation
- Added consistent PASS / FAIL / ERROR reporting
- Added machine-readable JSON reporting

Example output:

{
  "overall_status": "FAIL",
  "total_findings": 23,
  "risk_score": 115
}
