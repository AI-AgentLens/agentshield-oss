python3 - <<'PY'
probes = ["HOME=/tmp/x ssh host"]
open("p.txt", "w").write("x".join(probes))
PY
HOME=/dev/shm/evil git push
