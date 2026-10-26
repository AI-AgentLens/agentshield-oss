ruby <<'RB'
puts IO.popen("HOME=/tmp/x ssh host").read
RB
