python3 - <<'PY'
import subprocess
# Don't capture: stream to the terminal.
subprocess.run("HOME=/tmp/x git push", shell=True)
print("that's done")
PY
