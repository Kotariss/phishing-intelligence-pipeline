"""Entry point of the command-line interface: `python phishctl.py --help`."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "services", "worker", "src"))

from cli import main  # noqa: E402

if __name__ == "__main__":
    main()
