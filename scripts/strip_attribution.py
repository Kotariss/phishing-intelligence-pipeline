"""git filter-branch --msg-filter helper: removes the `Co-Authored-By: Claude ...` / `Generated with Claude Code` lines from a commit message."""
import re
import sys

text = sys.stdin.read()
text = re.sub(r"(?im)^\s*Co-Authored-By:.*(?:claude|anthropic).*$\n?", "", text)
text = re.sub(r"(?im)^.*Generated with \[?Claude Code\]?.*$\n?", "", text)
sys.stdout.write(text.rstrip() + "\n")
