"""
Internal billing/backend service.
Should NEVER be reachable from outside the internal-net.
No authentication — relies entirely on network isolation.
This is the SSRF pivot target.
"""
import os
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    return jsonify({
        "service": "internal-billing",
        "warning": "THIS ENDPOINT SHOULD NOT BE PUBLICLY REACHABLE",
        "data": {
            "tenant_records": [
                {"tenant_id": "t-001", "plan": "enterprise", "monthly_spend": 9999.00},
                {"tenant_id": "t-002", "plan": "pro",        "monthly_spend": 149.00},
            ],
            "platform_secrets": {
                "db_password":       os.environ.get("DB_PASSWORD", "password"),
                "internal_api_key":  os.environ.get("INTERNAL_API_KEY", "int-key-9999"),
                "public_key": "fake-token",
            }
        }
    })

@app.route('/health')
def health():
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000)
