python3 - <<'PY'
import pty
pty.spawn(["sh", "-c", "HOME=/tmp/x ssh host"])
PY
