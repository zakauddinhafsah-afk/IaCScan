
import hcl2
import json
import re


def clean_value(value):
    if isinstance(value, bool):
        return str(value).lower()

    if isinstance(value, str):
        if value.startswith('"') and value.endswith('"'):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value[1:-1]

    if isinstance(value, (int, float)):
        return str(value)

    return value


def find_resource_line(lines, resource_type, resource_name):
    pattern = re.compile(
        r'^\s*resource\s+["\']'
        + re.escape(resource_type)
        + r'["\']\s+["\']'
        + re.escape(resource_name)
        + r'["\']'
    )

    for number, line in enumerate(lines, start=1):
        if pattern.search(line):
            return number

    return 1


def find_attribute_line(lines, key, start_line):
    pattern = re.compile(
        r'^\s*' + re.escape(key) + r'\s*='
    )

    for number in range(start_line, len(lines) + 1):
        if pattern.search(lines[number - 1]):
            return number

    return start_line


def parse_file(path):
    resources = []

    with open(path, "r", encoding="utf-8") as file:
        source = file.read()

    lines = source.splitlines()
    data = hcl2.loads(source)

    for resource_group in data.get("resource", []):
        for resource_type, instances in resource_group.items():

            resource_type = clean_value(resource_type)

            for resource_name, config in instances.items():
                resource_name = clean_value(resource_name)

                resource_line = find_resource_line(
                    lines, resource_type, resource_name
                )

                resource = {
                    "type": resource_type,
                    "name": resource_name,
                    "file": str(path),
                    "line": resource_line,
                    "attrs": {},
                    "blocks": []
                }

                for key, value in config.items():
                    if key == "__is_block__":
                        continue

                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                block_attrs = {
                                    k: (
                                        clean_value(v),
                                        resource_line
                                    )
                                    for k, v in item.items()
                                    if k != "__is_block__"
                                }

                                resource["blocks"].append({
                                    "kind": key,
                                    "line": resource_line,
                                    "attrs": block_attrs
                                })

                    else:
                        attr_line = find_attribute_line(
                            lines, key, resource_line
                        )

                        resource["attrs"][key] = (
                            clean_value(value),
                            attr_line
                        )

                resources.append(resource)

    return resources
def parse_modules(path):
    with open(path, "r", encoding="utf-8") as file:
        source = file.read()

    data = hcl2.loads(source)
    modules = []

    for module_group in data.get("module", []):
        for module_name, config in module_group.items():
            source = config.get("source")

            if isinstance(source, str):
                source = clean_value(source)
                if source.startswith("./") or source.startswith("../"):
                    modules.append(source)

    return modules
