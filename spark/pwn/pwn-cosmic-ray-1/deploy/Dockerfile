FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/ubuntu.sources; do \
        if [ -f "$f" ]; then \
            sed -i \
                -e 's|http://archive.ubuntu.com|http://mirrors.tuna.tsinghua.edu.cn|g' \
                -e 's|http://security.ubuntu.com|http://mirrors.tuna.tsinghua.edu.cn|g' \
                "$f"; \
        fi; \
    done; \
    apt-get update; \
    apt-get -y dist-upgrade; \
    apt-get install -y --no-install-recommends \
        xinetd python3 python3-pip python3-venv \
        ca-certificates build-essential cmake; \
    rm -rf /var/lib/apt/lists/*

COPY ./requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

RUN useradd -m -s /bin/bash ctf

WORKDIR /home/ctf

COPY ./bin/ /home/ctf/
COPY ./service.sh /home/ctf/service.sh

COPY ./xinetd/ /etc/xinetd.d/
COPY ./start.sh /start.sh

RUN echo "Blocked by ctf" > /etc/banner_fail

RUN chmod +x /home/ctf/service.sh /start.sh && \
    chown -R root:ctf /home/ctf && \
    chmod -R 770 /home/ctf && \
    chmod 760 /home/ctf/flag

CMD ["/start.sh"]

EXPOSE 9999
