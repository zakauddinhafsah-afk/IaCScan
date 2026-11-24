from pathlib import Path
from parser import parse_modules


def find_tf_files(folder):
    root = Path(folder).resolve()

    visited = set()
    tf_files = set()

    def scan_directory(directory):
        directory = directory.resolve()

        if directory in visited or not directory.is_dir():
            return

        visited.add(directory)

        for tf_file in sorted(directory.rglob("*.tf")):
            if ".terraform" in tf_file.parts:
                continue

            tf_file = tf_file.resolve()

            if tf_file in tf_files:
                continue

            tf_files.add(tf_file)

            for module_source in parse_modules(tf_file):
                module_path = (tf_file.parent / module_source).resolve()

                if module_path.is_dir():
                    scan_directory(module_path)

    scan_directory(root)

    return sorted(tf_files)


if __name__ == "__main__":
    for f in find_tf_files("tests/lab1"):
        print(f)
