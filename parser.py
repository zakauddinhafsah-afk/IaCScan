import re

# Pattern: resource "TYPE" "NAME" {
RESOURCE_START = re.compile(r'^\s*resource\s+"(.+?)"\s+"(.+?)"\s*\{')
# Pattern: ingress {   (nested block ki shuruaat)
NESTED_START = re.compile(r'^\s*(\w+)\s*\{')
# Pattern: key = value
ATTRIBUTE = re.compile(r'^\s*(\w+)\s*=\s*(.+?)\s*$')

def clean_value(value):
    # Quotes hata do: "public-read" -> public-read
    return value.strip().strip('"')

def parse_file(path):
    resources = []
    with open(path) as f:
        lines = f.readlines()

    current = None   # abhi kaunsa resource parh rahe hain
    nested = None    # abhi kaunsa nested block (ingress wagaira)
    depth = 0        # brace depth

    for line_no, line in enumerate(lines, start=1):
        if current is None:
            match = RESOURCE_START.match(line)
            if match:
                current = {
                    "type": match.group(1),
                    "name": match.group(2),
                    "file": str(path),
                    "line": line_no,
                    "attrs": {},
                    "blocks": [],
                }
                depth = 1
            continue

        # Nested block shuru hua? (sirf resource ke seedhe andar)
        nested_match = NESTED_START.match(line)
        if nested_match and nested is None and depth == 1:
            nested = {"kind": nested_match.group(1), "line": line_no, "attrs": {}}

        # Attribute dhoondo
        attr = ATTRIBUTE.match(line)
        if attr:
            target = nested["attrs"] if nested else current["attrs"]
            target[attr.group(1)] = (clean_value(attr.group(2)), line_no)

        # Brace depth update karo
        depth += line.count("{") - line.count("}")

        # Nested block khatam hua? (depth wapas 1 par aa gaya)
        if nested is not None and depth == 1:
            current["blocks"].append(nested)
            nested = None

        # Resource khatam hua?
        if depth == 0:
            resources.append(current)
            current = None

    return resources

if __name__ == "__main__":
    for r in parse_file("tests/lab1/network/sg.tf"):
        print(r)
