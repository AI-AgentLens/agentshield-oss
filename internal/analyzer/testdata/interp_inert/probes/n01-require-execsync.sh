node - <<'JS'
require("child_process").execSync("HOME=/tmp/x ssh host", { stdio: "inherit" });
JS
