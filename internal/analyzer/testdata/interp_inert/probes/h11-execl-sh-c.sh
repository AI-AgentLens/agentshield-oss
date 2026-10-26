python3 - <<'PY'
import os
os.execl("/bin/sh", "sh", "-c", "HOME=/tmp/x ssh host")
PY
