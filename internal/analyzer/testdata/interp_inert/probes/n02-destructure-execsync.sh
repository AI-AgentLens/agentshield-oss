node - <<'JS'
const { execSync } = require("child_process");
execSync("export HOME=/tmp/x; ssh host");
JS
