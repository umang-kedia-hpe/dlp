FROM mitmproxy/mitmproxy

USER root
RUN apt-get update && apt-get install -y iptables procps

COPY egress/dlp.py /scripts/dlp.py
COPY ../utilkit.py /scripts/utilkit.py
COPY egress/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]