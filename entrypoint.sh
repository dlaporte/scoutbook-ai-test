#!/bin/sh
# Fix ownership of mounted volumes (may be root-owned from prior deployments),
# then drop privileges to the non-root mcp user.
if [ "$(id -u)" = "0" ]; then
    chown -R mcp:mcp /data 2>/dev/null || true
    export HOME=/home/mcp
    exec python3 -c "
import os, sys
os.setgid(1000)
os.setuid(1000)
os.environ['HOME'] = '/home/mcp'
os.execvp(sys.argv[1], sys.argv[1:])
" "$@"
fi
exec "$@"
