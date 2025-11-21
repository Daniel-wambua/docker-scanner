import argparse
import sys
from checks.dockerfile_checks import run_dockerfile_checks
from checks.compose_checks import run_compose_checks
from checks.container_runtime_checks import run_runtime_checks
from utils.file_loader import load_dockerfile, load_compose_file
from utils.report import print_findings, print_banner


def parse_args():
    parser = argparse.ArgumentParser(
        description="Docker & Container Misconfiguration Scanner"
    )
    parser.add_argument(
        "--dockerfile",
        help="Path to Dockerfile to scan"
    )
    parser.add_argument(
        "--compose",
        help="Path to docker-compose file to scan"
    )
    parser.add_argument(
        "--runtime",
        action="store_true",
        help="Scan running containers"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    
    if not args.json:
        print_banner()
    
    if not any([args.dockerfile, args.compose, args.runtime]):
        print("Error: Specify at least one scan type (--dockerfile, --compose, --runtime)")
        sys.exit(1)
    
    all_findings = []
    
    if args.dockerfile:
        try:
            lines = load_dockerfile(args.dockerfile)
            findings = run_dockerfile_checks(lines)
            all_findings.extend(findings)
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)
    
    if args.compose:
        try:
            config = load_compose_file(args.compose)
            findings = run_compose_checks(config)
            all_findings.extend(findings)
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Error parsing compose file: {e}")
            sys.exit(1)
    
    if args.runtime:
        findings = run_runtime_checks()
        all_findings.extend(findings)
    
    print_findings(all_findings, as_json=args.json)
    
    if all_findings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
