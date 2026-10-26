node - <<'JS'
const child_process = require("child_process");
// don't buffer
child_process.execSync("HOME=/tmp/x ssh host", { stdio: "inherit" });
console.log(`it's done`);
JS
