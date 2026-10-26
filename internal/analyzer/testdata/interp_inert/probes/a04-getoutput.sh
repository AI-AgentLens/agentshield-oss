python3 - <<'PY'
import subprocess
print(subprocess.getoutput("adb shell am start -a android.intent.action.VIEW -d http://x.com;id"))
PY
