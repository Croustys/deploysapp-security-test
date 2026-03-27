FROM python:3.12-slim
RUN pip install --no-cache-dir locust requests
COPY locustfile.py /locustfile.py
COPY scenarios/ /scenarios/
COPY resource-exhaust.sh /resource-exhaust.sh
RUN chmod +x /resource-exhaust.sh
CMD ["locust", "--headless", "-f", "/locustfile.py", "--host=http://traefik:80", "-u", "50", "-r", "10", "--run-time", "60s"]
