#!/bin/sh
# TRIDENT verification: lint + full test suite + fixture integrity.
set -e
cd "$(dirname "$0")/.."

echo "== fixture integrity =="
python - <<'PY'
import hashlib, pathlib, sys
expected = {
    "tests/fixtures/sample_lab.pkt": "4a212faa24258ee7",
    "tests/fixtures/sample_activity.pka": "3b05bf9fb9c0c51b",
}
ok = True
for path, want in expected.items():
    got = hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()[:16]
    status = "OK" if got == want else "MODIFIED"
    if got != want:
        ok = False
    print(f"  {path}: {got} [{status}]")
sys.exit(0 if ok else 1)
PY

echo
echo "== lint =="
ruff check trident/ tests/

echo
echo "== tests =="
python -m pytest -q

echo
echo "ALL CHECKS PASSED"
