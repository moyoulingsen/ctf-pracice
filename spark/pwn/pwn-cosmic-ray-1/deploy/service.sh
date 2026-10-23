#!/bin/sh
export HOME=/home/ctf
export TERM=dumb
cd /home/ctf || exit 1
# 优先使用 xinetd 透传的环境变量；拿不到则回退到启动时记录的值
if [ -z "$ROUND" ] && [ -r /etc/ctf_round ]; then
    ROUND="$(cat /etc/ctf_round)"
    export ROUND
fi
if [ -z "$BLOCK_LIMIT" ] && [ -r /etc/ctf_block_limit ]; then
    BLOCK_LIMIT="$(cat /etc/ctf_block_limit)"
    export BLOCK_LIMIT
fi
exec /opt/venv/bin/python3 ./chal.py
