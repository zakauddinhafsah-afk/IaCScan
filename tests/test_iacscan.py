import subprocess, sys

def test_scan_runs(tmp_path):
    out = tmp_path / "report.txt"
    r = subprocess.run(
        [sys.executable, "iacscan.py", "tests", "-o", str(out)],
        capture_output=True, text=True)
    assert r.returncode in (0, 1)
    assert out.exists()
    assert out.read_text().strip() != ""
