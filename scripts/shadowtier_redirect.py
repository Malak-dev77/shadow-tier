import subprocess
import time
import re
LOG_FILE = '/var/log/suricata/fast.log'
DECEPTION IP 192.168.30.2'
redirected = set()
print('[SHADOW TIER] Redirect engine started watching for alerts...')
with open(LOG_FILE, 'r') as f:
f.seek (0, 2)
while True:
line f.readline()
if not line:
time.sleep(0.5)
continue
if 'SHADOWTIER' in line:
match = re.search(r'\{TCP\}\s+(\d+\.\d+\,\d+\,\d+): \d+\s+->', line)
if match:
attacker_ip match.group (1)
if attacker_ip not in redirected:
print (f' [SHADOW TIER) Attacker detected: {attacker_ip} redirecting to maze')
cmd = f'iptables -t nat -A PREROUTING -s {attacker_ip}j DNAT-to-destination {DECEPTION_IP}'
subprocess.run(cmd, shell=True)
redirected.add(attacker_ip)
print (f' [SHADOW TIER] (attacker_ip} now inside the maze')
