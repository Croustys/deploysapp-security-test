FROM python:3.12-slim
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /sqlmap
COPY run.sh /run.sh
RUN chmod +x /run.sh
CMD ["/run.sh"]
