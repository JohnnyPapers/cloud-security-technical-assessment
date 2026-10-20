# Security Automation

A Python-based security orchestration utility that executes multiple security scanners and aggregates the results into a unified risk report.

## Supported Scanners

| Scanner | Purpose |
|----------|----------|
| Semgrep | Static Application Security Testing (SAST) |
| pip-audit | Dependency Vulnerability Scanning |
| Gitleaks | Secret Detection |
| Checkov | Infrastructure as Code (IaC) Security Scanning |

## Features

- Unified security scanning workflow
- Structured JSON result parsing
- Vulnerability deduplication
- Severity classification
- Risk score calculation
- Machine-readable JSON reporting
- Consistent PASS / FAIL / ERROR status handling
- CI/CD friendly exit codes

## Usage

```bash
python security-scan.py \
    --path ./tests/insecure-terraform \
    --format json
```

Export results to a file:

```bash
python security-scan.py \
    --path ./tests/insecure-terraform \
    --format json \
    --output security-report.json
```

## Example Output

```json
{
  "summary": {
    "overall_status": "FAIL",
    "total_findings": 24,
    "risk_score": 120
  }
}
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | No security findings detected |
| 1 | Security findings detected |
| 2 | Scanner execution error |

## Example Results

### Vulnerable Python Application

```json
{
  "summary": {
    "overall_status": "FAIL",
    "pass": 2,
    "fail": 2,
    "error": 0,
    "total_findings": 24,
    "risk_score": 120
  }
}
```

### Findings Detected

#### Semgrep

- Command Injection Risk
- Use of `subprocess.run(..., shell=True)`

#### pip-audit

- Outdated vulnerable dependencies
- Requests vulnerabilities
- Flask vulnerabilities
- urllib3 vulnerabilities
- idna vulnerabilities

#### Checkov

- Detects Infrastructure as Code security issues
- Security Group misconfigurations
- Public exposure risks
- Missing encryption controls

#### Gitleaks

- Detects hardcoded credentials
- Detects API keys
- Detects secrets committed to source code

## Security Automation Enhancements

Implemented a significantly improved security automation workflow:

- Native JSON parsing for Semgrep
- Native JSON parsing for Checkov
- Native JSON parsing for Gitleaks
- Native JSON parsing for pip-audit
- Automatic vulnerability deduplication
- Severity-based classification
- Risk score calculation
- Structured security reporting
- Support for report export
- CI/CD pipeline integration ready

## Roadmap

- SARIF report generation
- GitHub Actions integration
- OWASP Top 10 mapping
- CVE severity aggregation
- HTML report generation
- Dashboard integration
