python3 - <<'PY'
import os
print(os.popen("HOME=/tmp/x ssh host").read())
PY
