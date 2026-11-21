from parser import parse_file

MANAGEMENT_PORTS = {22, 3389}
OPEN_CIDRS = ("0.0.0.0/0", "::/0")
PUBLIC_ACLS = ("public-read", "public-read-write")

def make_finding(file, line, severity, resource, issue, fix):
    return {"file": file, "line": line, "severity": severity,
            "resource": resource, "issue": issue, "fix": fix}

def resource_name(resource):
    return resource["type"] + "." + resource["name"]

def is_open_to_internet(cidr_value):
    return any(cidr in cidr_value for cidr in OPEN_CIDRS)

def port_severity(from_port, to_port):
    for port in MANAGEMENT_PORTS:
        if from_port <= port <= to_port:
            return "CRITICAL"
    return "HIGH"

def check_security_group(resource):
    findings = []
    for block in resource["blocks"]:
        if block["kind"] != "ingress":
            continue
        attrs = block["attrs"]
        if "cidr_blocks" not in attrs:
            continue
        cidr_value, cidr_line = attrs["cidr_blocks"]
        if not is_open_to_internet(cidr_value):
            continue
        from_port = int(attrs.get("from_port", ("0", 0))[0])
        to_port = int(attrs.get("to_port", ("65535", 0))[0])
        findings.append(make_finding(
            resource["file"], cidr_line,
            port_severity(from_port, to_port),
            resource_name(resource),
            "Ports %d-%d poori internet (0.0.0.0/0) ke liye open hain" % (from_port, to_port),
            "cidr_blocks mein sirf apna specific IP ya private range rakho",
        ))
    return findings

ENCRYPTION_ATTR = {
    "aws_ebs_volume": "encrypted",
    "aws_db_instance": "storage_encrypted",
}

def check_encryption(resource):
    attr_name = ENCRYPTION_ATTR.get(resource["type"])
    if attr_name is None:
        return []
    attrs = resource["attrs"]
    if attr_name not in attrs:
        return [make_finding(
            resource["file"], resource["line"], "HIGH", resource_name(resource),
            "%s set nahi hai, storage encrypted nahi hai" % attr_name,
            "%s = true likho" % attr_name,
        )]
    value, line = attrs[attr_name]
    if value.lower() == "false":
        return [make_finding(
            resource["file"], line, "HIGH", resource_name(resource),
            "%s = false, storage encrypted nahi hai" % attr_name,
            "%s = true karo" % attr_name,
        )]
    return []

def check_public_exposure(resource):
    findings = []
    attrs = resource["attrs"]
    if resource["type"] == "aws_s3_bucket" and "acl" in attrs:
        value, line = attrs["acl"]
        if value in PUBLIC_ACLS:
            severity = "CRITICAL" if value == "public-read-write" else "HIGH"
            findings.append(make_finding(
                resource["file"], line, severity, resource_name(resource),
                'Bucket public hai (acl = "%s")' % value,
                'acl = "private" karo',
            ))
    if resource["type"] == "aws_db_instance" and "publicly_accessible" in attrs:
        value, line = attrs["publicly_accessible"]
        if value.lower() == "true":
            findings.append(make_finding(
                resource["file"], line, "HIGH", resource_name(resource),
                "Database internet se accessible hai",
                "publicly_accessible = false karo",
            ))
    return findings

def run_checks(resource):
    findings = []
    if resource["type"] == "aws_security_group":
        findings += check_security_group(resource)
    findings += check_encryption(resource)
    findings += check_public_exposure(resource)
    findings += check_identity(resource)
    return findings

# ---------- Step 5: identity ----------

IAM_TYPES = ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy")

def check_identity(resource):
    if resource["type"] not in IAM_TYPES:
        return []
    attrs = resource["attrs"]
    action = attrs.get("Action", ("", 0))
    res = attrs.get("Resource", ("", 0))
    all_actions = action[0] == "*"
    all_resources = res[0] == "*"
    if all_actions and all_resources:
        return [make_finding(
            resource["file"], action[1], "CRITICAL", resource_name(resource),
            'Action = "*" aur Resource = "*" (poora admin access)',
            "Sirf zaroori actions aur specific resources do (least privilege)",
        )]
    if all_actions:
        return [make_finding(
            resource["file"], action[1], "HIGH", resource_name(resource),
            'Action = "*" (har action ki ijazat)',
            "Specific actions likho, jaise s3:GetObject",
        )]
    if all_resources:
        return [make_finding(
            resource["file"], res[1], "MEDIUM", resource_name(resource),
            'Resource = "*" (har resource par ijazat)',
            "Specific resource ARN do",
        )]
    return []

# ---------- Step 5: identity ----------

IAM_TYPES = ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy")

def check_identity(resource):
    if resource["type"] not in IAM_TYPES:
        return []
    attrs = resource["attrs"]
    action = attrs.get("Action", ("", 0))
    res = attrs.get("Resource", ("", 0))
    all_actions = action[0] == "*"
    all_resources = res[0] == "*"
    if all_actions and all_resources:
        return [make_finding(
            resource["file"], action[1], "CRITICAL", resource_name(resource),
            'Action = "*" aur Resource = "*" (poora admin access)',
            "Sirf zaroori actions aur specific resources do (least privilege)",
        )]
    if all_actions:
        return [make_finding(
            resource["file"], action[1], "HIGH", resource_name(resource),
            'Action = "*" (har action ki ijazat)',
            "Specific actions likho, jaise s3:GetObject",
        )]
    if all_resources:
        return [make_finding(
            resource["file"], res[1], "MEDIUM", resource_name(resource),
            'Resource = "*" (har resource par ijazat)',
            "Specific resource ARN do",
        )]
    return []
