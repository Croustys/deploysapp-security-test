FROM alpine:latest
RUN apk add --no-cache curl
COPY secrets.sh /secrets.sh
RUN chmod +x /secrets.sh
CMD ["/secrets.sh"]
