"""
Simulates the AWS EC2 Instance Metadata Service (IMDS).
Bound on port 80 — reachable at http://metadata.internal/
(In a real cloud environment this would be 169.254.169.254)

This is the SSRF → cloud credential theft target.
If an attacker can reach this via SSRF from the vulnerable-webapp,
they can steal fake IAM credentials.
"""
from flask import Flask, jsonify, Response

app = Flask(__name__)

IAM_ROLE = "deploysapp-ec2-role"

# Fake AWS credentials — clearly labelled as fake
FAKE_CREDENTIALS = {
    "Code":            "Success",
    "LastUpdated":     "2026-01-01T00:00:00Z",
    "Type":            "AWS-HMAC",
    "AccessKeyId":     "AKIAIOSFODNN7EXAMPLE",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Token":           "AQoXnyc4lcK4w4OIaHXMSIXXXXXXXXXXX//FAKETOKEN",
    "Expiration":      "2099-01-01T00:00:00Z"
}

@app.route('/latest/meta-data/')
def metadata_root():
    return Response("iam/\nhostname\ninstance-id\nlocal-ipv4\n", mimetype='text/plain')

@app.route('/latest/meta-data/iam/')
def iam():
    return Response(f"security-credentials/\n", mimetype='text/plain')

@app.route('/latest/meta-data/iam/security-credentials/')
def creds_list():
    return Response(IAM_ROLE, mimetype='text/plain')

@app.route(f'/latest/meta-data/iam/security-credentials/{IAM_ROLE}')
def creds():
    # This is what an attacker retrieves via SSRF
    return jsonify(FAKE_CREDENTIALS)

@app.route('/latest/meta-data/hostname')
def hostname():
    return Response("ip-10-0-0-1.ec2.internal", mimetype='text/plain')

@app.route('/latest/meta-data/instance-id')
def instance_id():
    return Response("i-1234567890abcdef0", mimetype='text/plain')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
