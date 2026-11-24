# IaCScan

IaCScan is a Python-based command-line security scanner for Infrastructure as Code (IaC). It scans Terraform (.tf) files and identifies common security misconfigurations before deployment.

## Features

- Recursively scans Terraform files.
- Parses Terraform resources and attributes using Python HCL2.
- Detects security misconfigurations.
- Reports severity levels: CRITICAL, HIGH, MEDIUM, and LOW.
- Displays file names and line numbers.
- Generates text and JSON reports.

## Security Checks

| Security Check | Resource Types | Severity |
|---|---|---|
| Open security group ingress | aws_security_group | CRITICAL / HIGH |
| Storage without encryption | aws_ebs_volume, aws_db_instance | HIGH |
| Publicly exposed storage | aws_s3_bucket, aws_db_instance | HIGH |
| Overly broad IAM permissions | aws_iam_policy, aws_iam_role_policy, aws_iam_user_policy | CRITICAL / HIGH / MEDIUM |

## Requirements

- Python 3
- pip
- Python virtual environment

## Installation

Clone the repository:

```bash
git clone https://github.com/zakauddinhafsah-afk/IaCScan.git
cd IaCScan
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```
## Usage

Scan a folder:

```bash
python iacscan.py tests -o report.txt
```

Generate a JSON report:

```bash
python iacscan.py tests --format json -o report.json
```

IaCScan searches recursively for Terraform files and displays detected findings in the terminal while saving the report.

## Testing

Run automated tests:

```bash
python -m pytest -v
```

## Project Structure

- `iacscan.py` — CLI entry point and report generation.
- `scanner.py` — Recursively discovers Terraform files.
- `parser.py` — Parses Terraform resources and attributes.
- `checks.py` — Contains security detection rules.
- `tests/` — Terraform test fixtures and automated tests.
- `requirements.txt` — Python dependencies.

## Limitations

IaCScan is an educational project. It does not fully evaluate Terraform variables, module references, or complex expressions. Some complex IAM policies may not be detected by its current pattern-based checks. Line-number accuracy for nested block attributes may also be limited.

## Lab Use Only

Use IaCScan only on Terraform files you own or have permission to scan. The included test files are created for educational testing purposes.
