import os
import sys
import tempfile

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_TMP = tempfile.mkdtemp(prefix="phish_tests_")

# Deterministic, offline, isolated test environment (must be set before the worker modules load).
os.environ["LLM_MODE"] = "off"
os.environ["SANDBOX_INPROCESS_FALLBACK"] = "true"
os.environ["SANDBOX_HOST"] = "127.0.0.1"
os.environ["SANDBOX_PORT"] = "1"  # nothing listens there -> in-process extractors
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(_TMP, 'test.db')}"
os.environ["EXPORTS_DIR"] = os.path.join(_TMP, "exports")
os.environ["LOGS_DIR"] = os.path.join(_TMP, "logs")

for path in (os.path.join(ROOT_DIR, "services", "worker", "src"),
             os.path.join(ROOT_DIR, "services", "sandbox", "src"),
             os.path.join(ROOT_DIR, "tests", "fixtures")):
    if path not in sys.path:
        sys.path.insert(0, path)

DATASET_DIR = os.path.join(ROOT_DIR, "file_for_case")
