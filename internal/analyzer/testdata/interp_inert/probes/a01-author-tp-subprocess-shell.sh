python3 - <<'PY'
import subprocess
subprocess.run("adb shell am start -a android.intent.action.VIEW -d http://x.com;id", shell=True)
PY
