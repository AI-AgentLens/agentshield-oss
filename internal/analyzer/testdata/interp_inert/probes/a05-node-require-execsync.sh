node - <<'JS'
require("child_process").execSync("adb shell am start -a android.intent.action.VIEW -d http://x.com;id");
JS
