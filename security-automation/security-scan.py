#!/usr/bin/env python3

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

from datetime import UTC, datetime
from pathlib import Path


def tool_result(name):
    """Create the standard result structure."""

    return {
        "name": name,
        "status": "PASS",
        "severity": "INFO",
        "findings": 0,
        "return_code": None,
        "output": [],
        "error": ""
    }


def resolve_command(command):
    """
    Resolve a command from PATH.

    Raises FileNotFoundError when the executable cannot be found.
    """

    executable = shutil.which(command)

    if executable is None:
        raise FileNotFoundError(f"{command} is not installed or not in PATH")

    return executable


def execute(command):
    """Run a command and return the completed process."""

    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False
    )


def parse_json_output(output):
    """
    Parse JSON output.

    Some command-line tools may accidentally include whitespace or
    non-JSON text before the JSON document. First attempt direct parsing,
    then attempt to locate the first JSON object or array.
    """

    text = output.strip()

    if not text:
        return None

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        object_position = text.find("{")
        array_position = text.find("[")

        positions = [
            position
            for position in (object_position, array_position)
            if position >= 0
        ]

        if not positions:
            raise

        return json.loads(text[min(positions):])


def run_semgrep(scan_path):
    """Run Semgrep and parse its JSON results."""

    result = tool_result("semgrep")

    try:
        semgrep = resolve_command("semgrep")

        completed = execute([
            semgrep,
            "--config",
            "auto",
            "--json",
            "--quiet",
            scan_path
        ])

        result["return_code"] = completed.returncode

        report = parse_json_output(completed.stdout) or {}
        findings = report.get("results", [])
        errors = report.get("errors", [])

        result["findings"] = len(findings)
        result["output"] = findings

        severity_order = {
            "INFO": 0,
            "WARNING": 1,
            "ERROR": 2
        }

        highest = "INFO"

        for finding in findings:

            severity = (
                finding
                .get("extra", {})
                .get("severity", "INFO")
            )

            if (
                severity in severity_order
                and
                severity_order[severity]
                > severity_order[highest]
            ):
                highest = severity

        result["severity"] = highest

        if errors:
            result["status"] = "ERROR"
            result["error"] = json.dumps(errors, indent=2)

        elif completed.returncode not in (0, 1):
            result["status"] = "ERROR"
            result["error"] = (
                completed.stderr.strip()
                or f"Semgrep exited with code {completed.returncode}"
            )

        elif findings:
            result["status"] = "FAIL"

    except FileNotFoundError as error:
        result["status"] = "ERROR"
        result["error"] = str(error)

    except json.JSONDecodeError as error:
        result["status"] = "ERROR"
        result["error"] = f"Could not parse Semgrep JSON: {error}"

    except Exception as error:
        result["status"] = "ERROR"
        result["error"] = str(error)

    return result


def run_gitleaks(scan_path):
    """Run Gitleaks and parse its JSON report file."""

    result = tool_result("gitleaks")

    try:
        gitleaks = resolve_command("gitleaks")

        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "gitleaks.json"

            completed = execute([
                gitleaks,
                "detect",
                "--source",
                scan_path,
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                "--exit-code",
                "1",
                "--no-banner"
            ])

            result["return_code"] = completed.returncode

            if report_path.exists() and report_path.stat().st_size > 0:
                with report_path.open(
                    "r",
                    encoding="utf-8",
                    errors="replace"
                ) as report_file:
                    findings = json.load(report_file)
            else:
                findings = []

            if not isinstance(findings, list):
                findings = []

            result["findings"] = len(findings)
            if findings:
                result["severity"] = "ERROR"
            result["output"] = findings

            if completed.returncode not in (0, 1):
                result["status"] = "ERROR"
                result["error"] = (
                    completed.stderr.strip()
                    or completed.stdout.strip()
                    or f"Gitleaks exited with code {completed.returncode}"
                )

            elif findings:
                result["status"] = "FAIL"

    except FileNotFoundError as error:
        result["status"] = "ERROR"
        result["error"] = str(error)

    except json.JSONDecodeError as error:
        result["status"] = "ERROR"
        result["error"] = f"Could not parse Gitleaks JSON: {error}"

    except Exception as error:
        result["status"] = "ERROR"
        result["error"] = str(error)

    return result


def extract_checkov_findings(report):
    """
    Extract failed checks from Checkov JSON.

    Checkov can return either:
    - a single report object, or
    - a list of framework report objects.
    """

    failed_checks = []

    if isinstance(report, list):
        reports = report
    elif isinstance(report, dict):
        reports = [report]
    else:
        reports = []

    for framework_report in reports:
        if not isinstance(framework_report, dict):
            continue

        results = framework_report.get("results", {})

        if not isinstance(results, dict):
            continue

        checks = results.get("failed_checks", [])

        if isinstance(checks, list):
            failed_checks.extend(checks)

    return failed_checks


def run_checkov(scan_path):
    """Run Checkov and parse its JSON results."""

    result = tool_result("checkov")

    try:
        checkov = resolve_command("checkov")

        completed = execute([
            checkov,
            "--directory",
            scan_path,
            "--output",
            "json",
            "--quiet"
        ])

        result["return_code"] = completed.returncode

        report = parse_json_output(completed.stdout)

        if report is None:
            if completed.returncode == 0:
                report = {}
            else:
                result["status"] = "ERROR"
                result["error"] = (
                    completed.stderr.strip()
                    or "Checkov produced no JSON report"
                )
                return result

        findings = extract_checkov_findings(report)

        result["findings"] = len(findings)
        if findings:
            result["severity"] = "ERROR"
        result["output"] = findings

        if completed.returncode not in (0, 1):
            result["status"] = "ERROR"
            result["error"] = (
                completed.stderr.strip()
                or f"Checkov exited with code {completed.returncode}"
            )

        elif findings:
            result["status"] = "FAIL"

    except FileNotFoundError as error:
        result["status"] = "ERROR"
        result["error"] = str(error)

    except json.JSONDecodeError as error:
        result["status"] = "ERROR"
        result["error"] = f"Could not parse Checkov JSON: {error}"

    except Exception as error:
        result["status"] = "ERROR"
        result["error"] = str(error)

    return result


def extract_pip_audit_findings(report):

    unique_findings = {}

    if not isinstance(report, dict):
        return []

    dependencies = report.get("dependencies", [])

    for dependency in dependencies:

        package_name = dependency.get("name", "")
        package_version = dependency.get("version", "")

        for vulnerability in dependency.get("vulns", []):

            vulnerability_id = vulnerability.get("id", "")

            key = (
                package_name,
                package_version,
                vulnerability_id
            )

            if key not in unique_findings:

                unique_findings[key] = {
                    "package": package_name,
                    "version": package_version,
                    "id": vulnerability_id,
                    "aliases": list(
                        set(
                            vulnerability.get(
                                "aliases",
                                []
                            )
                        )
                    ),
                    "fix_versions": list(
                        set(
                            vulnerability.get(
                                "fix_versions",
                                []
                            )
                        )
                    )
                }

    return list(
        unique_findings.values()
    )

def run_pip_audit(requirements_file):
    """Run pip-audit with the current Python interpreter."""

    result = tool_result("pip-audit")

    try:
        completed = execute([
            sys.executable,
            "-m",
            "pip_audit",
            "--requirement",
            requirements_file,
            "--format",
            "json",
            "--progress-spinner",
            "off"
        ])

        result["return_code"] = completed.returncode

        report = parse_json_output(completed.stdout)

        if report is None:
            result["status"] = "ERROR"
            result["error"] = (
                completed.stderr.strip()
                or "pip-audit produced no JSON report"
            )
            return result

        findings = extract_pip_audit_findings(report)

        result["findings"] = len(findings)
        result["output"] = findings

        if completed.returncode not in (0, 1):
            result["status"] = "ERROR"
            result["error"] = (
                completed.stderr.strip()
                or f"pip-audit exited with code {completed.returncode}"
            )

        elif findings:
            result["status"] = "FAIL"
            result["severity"] = "ERROR"

    except json.JSONDecodeError as error:
        result["status"] = "ERROR"
        result["error"] = f"Could not parse pip-audit JSON: {error}"

    except Exception as error:
        result["status"] = "ERROR"
        result["error"] = str(error)

    return result


def build_summary(results):

    pass_count = sum(
        1
        for result in results
        if result["status"] == "PASS"
    )

    fail_count = sum(
        1
        for result in results
        if result["status"] == "FAIL"
    )

    error_count = sum(
        1
        for result in results
        if result["status"] == "ERROR"
    )

    total_findings = sum(
        result["findings"]
        for result in results
    )

    risk_score = 0

    severity_weights = {
        "INFO": 1,
        "WARNING": 3,
        "ERROR": 5
    }

    for result in results:

        risk_score += (
            result["findings"]
            *
            severity_weights.get(
                result.get(
                    "severity",
                    "INFO"
                ),
                1
            )
        )

    if error_count > 0:
        overall_status = "ERROR"
    elif fail_count > 0:
        overall_status = "FAIL"
    else:
        overall_status = "PASS"

    return {
        "overall_status": overall_status,
        "pass": pass_count,
        "fail": fail_count,
        "error": error_count,
        "total_findings": total_findings,
        "risk_score": risk_score
    }

def print_text_report(report):
    """Print a concise terminal report."""

    summary = report["summary"]

    print("\n=== SECURITY SCAN SUMMARY ===")
    print(f"Path: {report['scan_path']}")
    print(f"Overall status: {summary['overall_status']}")
    print(f"Total findings: {summary['total_findings']}")
    print(
        f"PASS={summary['pass']} "
        f"FAIL={summary['fail']} "
        f"ERROR={summary['error']}"
    )

    print("\n=== TOOL RESULTS ===")

    for result in report["results"]:
        print(
            f"{result['name']}: "
            f"{result['status']} "
            f"(findings={result['findings']}, "
            f"return_code={result['return_code']})"
        )

        if result["error"]:
            print(f"  Error: {result['error']}")


def main():
    parser = argparse.ArgumentParser(
        description="Unified JSON Security Scanner"
    )

    parser.add_argument(
        "--path",
        required=True,
        help="Directory to scan"
    )

    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        help="Report output format"
    )

    parser.add_argument(
        "--output",
        help="Write report to file"
    )

    args = parser.parse_args()

    scan_path = os.path.abspath(args.path)

    if not os.path.isdir(scan_path):
        print(
            json.dumps({
                "error": f"Scan path does not exist or is not a directory: "
                         f"{scan_path}"
            }),
            file=sys.stderr
        )
        sys.exit(2)

    requirements_file = os.path.join(
        scan_path,
        "requirements.txt"
    )

    # Progress messages go to stderr so stdout remains valid JSON.
    print("Running semgrep...", file=sys.stderr)
    results = [run_semgrep(scan_path)]

    print("Running gitleaks...", file=sys.stderr)
    results.append(run_gitleaks(scan_path))

    print("Running checkov...", file=sys.stderr)
    results.append(run_checkov(scan_path))

    if os.path.isfile(requirements_file):
        print("Running pip-audit...", file=sys.stderr)
        results.append(
            run_pip_audit(requirements_file)
        )

    report = {
        "scan_time": datetime.now(UTC).isoformat(),
        "scan_path": scan_path,
        "summary": build_summary(results),
        "results": results
    }

    #
    # NEW CODE GOES HERE
    #
    if args.output:

        with open(
            args.output,
            "w",
            encoding="utf-8"
        ) as fp:

            json.dump(
                report,
                fp,
                indent=4
            )

        print(
            f"Report written to: {args.output}",
            file=sys.stderr
        )

    if args.format == "json":
        print(
            json.dumps(
                report, 
                indent=4,
                ensure_ascii=False
            )
        )
    else:
        print_text_report(report)

        if report["summary"]["overall_status"] == "PASS":
            sys.exit(0)

        if report["summary"]["overall_status"] == "FAIL":
            sys.exit(1)

        sys.exit(2)


if __name__ == "__main__":
    main()