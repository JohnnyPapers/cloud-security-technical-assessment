#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
from datetime import datetime


def run_tool(name, command):
    """
    Run a security tool and capture output
    """

    result = {
        "name": name,
        "status": "PASS",
        "return_code": None,
        "output": "",
        "error": ""
    }

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        result["return_code"] = completed.returncode
        result["output"] = completed.stdout

        if completed.returncode != 0:
            result["status"] = "FAIL"
            result["error"] = completed.stderr

    except FileNotFoundError:
        result["status"] = "ERROR"
        result["error"] = f"{name} not installed"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    return result


def build_summary(results):

    pass_count = len([r for r in results if r["status"] == "PASS"])
    fail_count = len([r for r in results if r["status"] == "FAIL"])
    error_count = len([r for r in results if r["status"] == "ERROR"])

    overall = "PASS"

    if fail_count > 0:
        overall = "FAIL"

    if error_count > 0:
        overall = "ERROR"

    return {
        "overall_status": overall,
        "pass": pass_count,
        "fail": fail_count,
        "error": error_count
    }


def main():

    parser = argparse.ArgumentParser(
        description="Unified Security Scanner"
    )

    parser.add_argument(
        "--path",
        required=True,
        help="Target directory"
    )

    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json"
    )

    args = parser.parse_args()

    results = []

    scans = [
        {
            "name": "semgrep",
            "command": [
                "semgrep",
                "--config",
                "auto",
                args.path
            ]
        },
        {
            "name": "pip-audit",
            "command": [
                "python",
                "-m",
                "pip_audit",
                "-r",
                f"{args.path}/requirements.txt"
            ]
        },
        {
            "name": "gitleaks",
            "command": [
                "gitleaks",
                "detect",
                "-s",
                args.path
            ]
        },
        {
            "name": "checkov",
            "command": [
                "checkov",
                "-d",
                args.path
            ]
        }
    ]

    for scan in scans:
        print(f"Running {scan['name']}...")
        results.append(
            run_tool(
                scan["name"],
                scan["command"]
            )
        )

    summary = build_summary(results)

    report = {
        "scan_time": datetime.utcnow().isoformat(),
        "scan_path": args.path,
        "summary": summary,
        "results": results
    }

    if args.format == "json":
        print(json.dumps(report, indent=4))
    else:
        print("\n==== SUMMARY ====")
        print(
            f"Overall Status: {summary['overall_status']}"
        )
        print(
            f"PASS={summary['pass']} "
            f"FAIL={summary['fail']} "
            f"ERROR={summary['error']}"
        )

    if summary["overall_status"] == "PASS":
        sys.exit(0)

    sys.exit(1)


if __name__ == "__main__":
    main()