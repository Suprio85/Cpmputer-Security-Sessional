import requests
r = requests.post("http://127.0.0.1:5000/verify", json={"pin": "0000"})
print(r.status_code, r.text)