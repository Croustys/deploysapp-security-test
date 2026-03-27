FROM projectdiscovery/nuclei:latest
COPY run.sh /run.sh
COPY templates/ /custom-templates/
RUN chmod +x /run.sh
ENTRYPOINT ["/run.sh"]
