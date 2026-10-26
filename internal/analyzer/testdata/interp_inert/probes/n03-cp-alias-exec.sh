node - <<'JS'
const cp = require("child_process");
cp.exec("HOME=/tmp/x git push", (e, out) => console.log(out));
JS
