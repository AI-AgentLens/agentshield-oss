python3 - <<'PY'
from subprocess import check_output
check_output("adb shell am start -a android.intent.action.VIEW -d http://x.com;id", shell=True)
PY
