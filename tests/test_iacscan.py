import subprocess, sys

def test_scan_runs(tmp_path):
    out = tmp_path / "report.txt"
    r = subprocess.run(
        [sys.executable, "iacscan.py", "tests", "-o", str(out)],
        capture_output=True, text=True)
    assert r.returncode in (0, 1)
    assert out.exists()
    assert out.read_text().strip() != ""
def test_hardcoded_password_detected(tmp_path):
    from checks import check_secrets

    resource = {
        "type": "aws_db_instance",
        "name": "test_db",
        "file": "test.tf",
        "line": 1,
        "attrs": {
            "password": ("DummyPassword123", 5)
        },
        "blocks": []
    }

    findings = check_secrets(resource)

    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert "password" in findings[0]["issue"]


def test_variable_password_not_detected():
    from checks import check_secrets

    resource = {
        "type": "aws_db_instance",
        "name": "test_db",
        "file": "test.tf",
        "line": 1,
        "attrs": {
            "password": ("var.db_password", 5)
        },
        "blocks": []
    }

    findings = check_secrets(resource)

    assert findings == []


def test_secret_value_not_exposed():
    from checks import check_secrets

    secret = "DummyPassword123"

    resource = {
        "type": "aws_db_instance",
        "name": "test_db",
        "file": "test.tf",
        "line": 1,
        "attrs": {
            "password": (secret, 5)
        },
        "blocks": []
    }

    findings = check_secrets(resource)

    assert secret not in str(findings)
def test_local_module_detection(tmp_path):
    from scanner import find_tf_files

    project = tmp_path / "project"
    module = project / "modules" / "network"

    module.mkdir(parents=True)

    root_file = project / "main.tf"
    root_file.write_text(
        'module "network" {\n'
        '  source = "./modules/network"\n'
        '}\n'
    )

    module_file = module / "network.tf"
    module_file.write_text(
        'resource "aws_security_group" "test" {}\n'
    )

    files = find_tf_files(project)

    assert root_file.resolve() in files
    assert module_file.resolve() in files
