python3 - <<'PY'
import os
print(os.popen("adb shell am start -a android.intent.action.VIEW -d http://x.com;id").read())
PY
