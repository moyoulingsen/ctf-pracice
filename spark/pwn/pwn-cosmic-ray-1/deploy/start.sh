#!/bin/sh
echo "$FLAG" > /home/ctf/flag
chown root:ctf /home/ctf/flag
chmod 740 /home/ctf/flag
export FLAG=""

# 记录容器启动时传入的 ROUND / BLOCK_LIMIT，供 xinetd 拉起的服务读取
echo "${ROUND:-1}" > /etc/ctf_round
chmod 644 /etc/ctf_round
echo "${BLOCK_LIMIT:-0}" > /etc/ctf_block_limit
chmod 644 /etc/ctf_block_limit

/etc/init.d/xinetd start
sleep infinity
