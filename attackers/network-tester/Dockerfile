FROM alpine:latest
RUN apk add --no-cache bash curl nmap netcat-openbsd
COPY pivot.sh /pivot.sh
RUN chmod +x /pivot.sh
CMD ["/pivot.sh"]
