python3 - <<'PY'
import os
# don't wait for the activity
os.system("adb shell am start -a android.intent.action.VIEW -d http://x.com;id")
# that's all
PY
