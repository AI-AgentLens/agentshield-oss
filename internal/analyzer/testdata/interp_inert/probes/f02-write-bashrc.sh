python3 - <<'PY'
import os
open(os.path.expanduser("~/.bashrc"), "a").write("export HOME=/tmp/x\n")
PY
