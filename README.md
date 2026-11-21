# IaCScan

A command-line Infrastructure-as-Code security scanner written in Python.
It reads Terraform (.tf) files and finds misconfigurations before they are deployed.

## What it checks

| Check | Resource types | Severity |
|---|---|---|
| Security group open to the internet (0.0.0.0/0, ::/0) | aws_security_group | CRITICAL for ports 22/3389, otherwise HIGH |
| Storage without encryption | aws_ebs_volume, aws_db_instance | HIGH |
| Publicly exposed storage | aws_s3_bucket, aws_db_instance | HIGH / CRITICAL |
| Overly broad IAM rights | aws_iam_policy, aws_iam_role_policy, aws_iam_user_policy | CRITICAL / HIGH / MEDIUM |

Every finding reports the file, line number, severity, the issue and a fix.

## How to run

    python3 iacscan.py <folder> -o report.txt

Example:

    python3 iacscan.py tests/lab1 -o report1.txt

The folder is searched recursively for .tf files. The report is printed and saved to the output file.

## Project layout

- iacscan.py - command line entry point and report writer
- scanner.py - finds .tf files in a folder (including nested folders)
- parser.py - extracts resource blocks, attributes and line numbers
- checks.py - the security checks
- tests/ - lab-only test files with planted flaws

## Limitations

This is a learning project. The parser reads the common Terraform layout line by line. It does not evaluate variables, modules or expressions.

## Lab use only

Run IaCScan only on files you own or have written permission to scan. The test files in tests/ are written by me for this purpose.
