FROM alpine:3.20

RUN apk add --no-cache tcpdump && mkdir -p /logs

# CMD ["tcpdump", "-i", "any", "-n", "-U"]
CMD ["tcpdump", "-i", "any", "-n", "-U", "-w", "/logs/pure_sandbox_traffic_%Y-%m-%d_%H-%M-%S.pcap", "-G", "3600", "-z", "gzip"]