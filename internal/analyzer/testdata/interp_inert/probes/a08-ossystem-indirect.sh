python3 - <<'PY'
import os
cmd = "adb shell am start -a android.intent.action.VIEW -d http://x.com;id"
os.system(cmd)
PY
