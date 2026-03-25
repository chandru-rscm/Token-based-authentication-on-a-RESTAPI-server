"""
JWT Auth API - Demo Test Script
Run this from the CLIENT laptop (or same laptop) to test all endpoints.

Usage:
    python test_demo.py                    # test on localhost
    python test_demo.py 192.168.x.x       # test on another laptop's IP
"""

import sys
import json
import urllib.request
import urllib.error

BASE_URL = f"http://{sys.argv[1] if len(sys.argv) > 1 else 'localhost'}:8000"

def pretty(label, data):
    print(f"\n{'='*50}")
    print(f"  {label}")
    print(f"{'='*50}")
    print(json.dumps(data, indent=2))

def post(path, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        BASE_URL + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read()), res.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code

def get(path, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    req = urllib.request.Request(BASE_URL + path, headers=headers)
    try:
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read()), res.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code

print(f"\n🔗 Testing JWT Auth API at: {BASE_URL}")

# 1. Health check
data, code = get("/")
pretty(f"[{code}] GET / — Health Check", data)

# 2. Register
data, code = post("/register", {"username": "chandru", "password": "secure123"})
pretty(f"[{code}] POST /register — Register User", data)

# 3. Register duplicate (should fail)
data, code = post("/register", {"username": "chandru", "password": "secure123"})
pretty(f"[{code}] POST /register — Duplicate User (expect 400)", data)

# 4. Login with wrong password (should fail)
data, code = post("/login", {"username": "chandru", "password": "wrongpass"})
pretty(f"[{code}] POST /login — Wrong Password (expect 401)", data)

# 5. Login correctly
data, code = post("/login", {"username": "chandru", "password": "secure123"})
pretty(f"[{code}] POST /login — Correct Login", data)
token = data.get("access_token", "")

# 6. Access protected with valid token
data, code = get("/protected", token=token)
pretty(f"[{code}] GET /protected — With Valid Token", data)

# 7. Access protected with fake token (should fail)
data, code = get("/protected", token="this.is.a.fake.token")
pretty(f"[{code}] GET /protected — With Invalid Token (expect 401)", data)

# 8. Access protected with no token (should fail)
data, code = get("/protected")
pretty(f"[{code}] GET /protected — No Token (expect 403)", data)

# 9. List users
data, code = get("/users")
pretty(f"[{code}] GET /users — Registered Users", data)

print("\n✅ Demo complete!")