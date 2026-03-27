"""
DoS / load test scenarios using Locust.
Tests rate limiting effectiveness and container resource limits.
"""
from locust import HttpUser, task, between
import random
import string


class NormalUser(HttpUser):
    """Simulates normal traffic to establish baseline."""
    wait_time = between(1, 3)
    host = "http://traefik:80"

    @task(3)
    def get_home(self):
        self.client.get("/", headers={"Host": "webapp.localhost"}, name="/")

    @task(2)
    def search(self):
        q = ''.join(random.choices(string.ascii_lowercase, k=5))
        self.client.get(f"/search?q={q}", headers={"Host": "webapp.localhost"}, name="/search")

    @task(1)
    def health(self):
        self.client.get("/health", headers={"Host": "webapp.localhost"}, name="/health")


class AggressiveUser(HttpUser):
    """Simulates rate-limit testing — sends requests as fast as possible."""
    wait_time = between(0.01, 0.05)
    host = "http://traefik:80"

    @task
    def flood_requests(self):
        self.client.get("/health", headers={"Host": "webapp.localhost"}, name="/health-flood")


class LargePayloadUser(HttpUser):
    """Tests large payload handling — potential DoS via body size."""
    wait_time = between(2, 5)
    host = "http://traefik:80"

    @task
    def large_post(self):
        # 1MB payload
        payload = "A" * 1_048_576
        self.client.post(
            "/upload",
            data={"file": ("bigfile.txt", payload, "text/plain")},
            headers={"Host": "webapp.localhost"},
            name="/upload-large",
            catch_response=True
        )
