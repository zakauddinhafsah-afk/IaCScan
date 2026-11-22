# IaCScan Demo and Write-up

Student: Hafsah Zaka | Track: Cloud Security | Instructor: Abdul Mannan

## 1. What I built

IaCScan is a Python command-line tool that reads Terraform (.tf) files and finds security misconfigurations before the infrastructure is deployed. It checks security groups, encryption, public exposure and IAM permissions, and saves a report with file, line number, severity and a fix for every finding.

## 2. Demo

All tests were run on my own lab files in tests/lab1 and tests/lab2. No real cloud account or third-party repository was scanned.

    python3 iacscan.py tests/lab1 -o report1.txt
    python3 iacscan.py tests/lab2 -o report2.txt

Result on lab1: 7 findings (2 CRITICAL, 5 HIGH).
Result on lab2: 2 findings (2 CRITICAL).

## 3. Planted flaws checklist (lab1)

| # | Planted flaw | File | Expected | Found |
|---|---|---|---|---|
| 1 | SSH open to 0.0.0.0/0 | network/sg.tf | CRITICAL | Yes, line 6 |
| 2 | IAM Action * and Resource * | iam.tf | CRITICAL | Yes, line 6 |
| 3 | Public bucket (public-read) | main.tf | HIGH | Yes, line 3 |
| 4 | EBS volume without encryption | storage.tf | HIGH | Yes, line 1 |
| 5 | Public bucket (public-read) | storage.tf | HIGH | Yes, line 12 |
| 6 | Database with storage_encrypted = false | storage.tf | HIGH | Yes, line 22 |
| 7 | Database publicly accessible | storage.tf | HIGH | Yes, line 23 |

Clean resources were not flagged: good_disk, private_one, least_privilege, and the 443 rule restricted to 10.0.0.0/16. This shows the checks do not raise false alarms on safe configuration.

## 4. One finding explained

Finding: [CRITICAL] tests/lab1/iam.tf:6 aws_iam_policy.broad
Issue: Action = "*" and Resource = "*" (full admin access)

What was wrong: The policy allows every action on every resource in the account. It is effectively administrator access written as a policy.

Why it is dangerous: If a user or role with this policy is compromised (for example through a leaked access key), the attacker can read data, delete resources, create new users and take over the whole cloud account. A mistake in one file becomes full account compromise.

The fix: Apply least privilege. Allow only the actions that are needed on only the resources that are needed. My least_privilege policy in the same file allows only s3:GetObject on one bucket, and IaCScan correctly does not flag it.

## 5. Testing I did

- Step 1: the file finder listed only the .tf files, including the nested folder, and not notes.txt.
- Step 2: the parser extracted type, name, attributes and correct line numbers, including nested ingress blocks.
- Step 3: with one open and one restricted rule, only the open rule was flagged.
- Step 4: planted flaws were flagged; after I fixed them the findings disappeared; after restoring them the findings came back.
- Step 5: the broad policy was flagged, the least-privilege policy was not.
- Step 6: the tool ran on two different folders and both reports were complete.

## 6. A bug I found and fixed

Running checks.py directly raised NameError: check_identity is not defined. The test block at the bottom of the file ran before the function was defined. I removed the old test block, since the real entry point is iacscan.py.

## 7. Limitations (honest reporting)

- It does not evaluate variables, modules or expressions.
- The parser is line based, so unusual formatting can be missed.
- The IAM check reads one Action and one Resource per policy, so policies with many statements are not fully covered.
- Public buckets are detected from the acl setting only, not from separate public access block resources.
- Only AWS resource types are covered.

## 8. Defensive lesson

See DEFENSIVE_LESSON.md: encryption by default, why it matters and how to enforce it.
