FROM instrumentisto/nmap:latest
RUN apk add --no-cache bash curl
COPY scan.sh /scan.sh
RUN chmod +x /scan.sh
CMD ["/scan.sh"]
