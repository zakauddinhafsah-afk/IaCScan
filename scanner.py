from pathlib import Path

def find_tf_files(folder):
    return sorted(Path(folder).rglob("*.tf"))

if __name__ == "__main__":
    for f in find_tf_files("tests/lab1"):
        print(f)
