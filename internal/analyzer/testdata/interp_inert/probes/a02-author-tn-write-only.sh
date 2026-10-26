python3 - <<'PY'
line = "adb shell am start -a android.intent.action.VIEW -d http://x.com;touch /tmp/p"
open("p.txt", "w").write(line)
PY
