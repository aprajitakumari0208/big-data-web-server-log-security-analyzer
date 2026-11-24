import random
from datetime import datetime
ips = ["192.168.1.10", "10.0.0.5", "172.16.0.22", "192.168.1.50"]
attacker_ips = ["203.0.113.5", "198.51.100.12"]
malicious_payloads = ["SELECT * FROM users WHERE id=1 OR 1=1 --", "<script>alert('XSS')</script>", "../etc/passwd"]
print("Generating server security logs...")
with open("server_access.log", "w") as f:
  for _ in range(2000):
     timestamp = datetime.now().strftime("[%d/%b/%Y:%H:%M:%S +0000]")
     f.write(f'203.0.113.5 - - {timestamp} "GET /index.html HTTP/1.1" 200 420\n')
  for _ in range(8000):
     is_attack = random.random() < 0.15
     ip = random.choice(attacker_ips) if is_attack else random.choice(ips)
     url = f"/login?user={random.choice(malicious_payloads)}" if is_attack else "/index.html"
     timestamp = datetime.now().strftime("[%d/%b/%Y:%H:%M:%S +0000]")
     f.write(f'{ip} - - {timestamp} "GET {url} HTTP/1.1" 200 500\n')
print("File 'server_access.log' created successfully.") 
