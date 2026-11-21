# Defensive Lesson: Encryption by Default

**What it is:** Storage (disks, databases, buckets) is encrypted automatically, so nobody has to remember to turn it on.

**Why it matters:** An unencrypted volume that leaks or is shared exposes its data in readable form. IaCScan found aws_ebs_volume.bad_disk with no encrypted setting, which is exactly how this mistake enters production: one forgotten line.

**How to enforce it:**
- Turn on account-level default EBS encryption in AWS.
- Set encrypted = true and storage_encrypted = true in every Terraform resource.
- Run a scanner like IaCScan in CI so an unencrypted resource fails the build before deployment.
