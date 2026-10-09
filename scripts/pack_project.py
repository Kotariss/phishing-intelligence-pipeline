import os
import zipfile

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ARCHIVE_NAME = "phishing-intelligence-pipeline.zip"
OUTPUT_PATH = os.path.join(ROOT_DIR, ARCHIVE_NAME)

INCLUDE_DIRS = ["docs", "services", "scripts", "tests", "exports"]
INCLUDE_FILES = ["README.md", "docker-compose.yml", ".env.example", ".gitignore"]

EXCLUDE_EXTS = {".pyc", ".db", ".log", ".tmp"}
EXCLUDE_DIRS = {"__pycache__", ".pytest_cache", ".git", ".idea", ".vscode"}


def should_include(rel_path):
    parts = rel_path.replace("\\", "/").split("/")
    for p in parts:
        if p in EXCLUDE_DIRS:
            return False
    _, ext = os.path.splitext(rel_path)
    if ext.lower() in EXCLUDE_EXTS:
        return False
    if rel_path.endswith(ARCHIVE_NAME) or rel_path.endswith(".zip"):
        return False
    return True


def pack():
    print(f"Creating archive: {OUTPUT_PATH}")
    total_files = 0
    total_bytes = 0

    with zipfile.ZipFile(OUTPUT_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1. Root files
        for fname in INCLUDE_FILES:
            fpath = os.path.join(ROOT_DIR, fname)
            if os.path.exists(fpath):
                zf.write(fpath, arcname=fname)
                total_files += 1
                total_bytes += os.path.getsize(fpath)
                print(f"  + {fname}")

        # 2. Directories
        for dname in INCLUDE_DIRS:
            dir_path = os.path.join(ROOT_DIR, dname)
            if not os.path.exists(dir_path):
                continue
            for root, dirs, files in os.walk(dir_path):
                # Filter out excluded dirs in-place
                dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
                for file in files:
                    full_p = os.path.join(root, file)
                    rel_p = os.path.relpath(full_p, ROOT_DIR)
                    if should_include(rel_p):
                        zf.write(full_p, arcname=rel_p)
                        total_files += 1
                        total_bytes += os.path.getsize(full_p)

    archive_size_mb = os.path.getsize(OUTPUT_PATH) / (1024 * 1024)
    print("\nPacking complete!")
    print(f"Total files packed: {total_files}")
    print(f"Uncompressed size: {total_bytes / (1024 * 1024):.2f} MB")
    print(f"Archive size: {archive_size_mb:.2f} MB")
    print(f"Location: {OUTPUT_PATH}")


if __name__ == "__main__":
    pack()
