FROM alpine:latest
RUN apk add --no-cache bash curl wget procps util-linux findutils
COPY escape-tests.sh /escape-tests.sh
COPY checks/ /checks/
RUN chmod +x /escape-tests.sh /checks/*.sh
CMD ["/escape-tests.sh"]
