import subprocess
import time
import re
import threading
from datetime import datetime, timedelta

LOG_FILE = '/var/log/suricata/fast.log'
DECEPTION_VM = '192.168.30.2'
CHALLENGE_GATE = '127.0.0.1:8080'
CONDITION_WINDOW_HOURS = 24

ip_state = {}
state_lock = threading.Lock()

SHADOWTIER_SIDS = {
    '1000001': 'persistence',
    '1000002': 'syn_scan',
    '1000003': 'login_targeting',
    '1000004': 'auth_targeting',
    '1000005': 'admin_targeting',
    '1000006': 'api_targeting'
}

def log(msg):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    entry = f'[{timestamp}] [COMMANDER] {msg}'
    print(entry)
    with open('/opt/shadowtier/logs/commander.log', 'a') as f:
        f.write(entry + '\n')

def run_cmd(cmd):
    subprocess.run(cmd, shell=True, capture_output=True)

def apply_state_1(ip):
    log(f'STATE 1 — {ip} — activating Layer Zero intensification')
    run_cmd(f'iptables -t nat -A PREROUTING -s {ip} -p tcp --dport 22 -j DNAT --to-destination 192.168.20.1:9999')
    run_cmd(f'iptables -t nat -A PREROUTING -s {ip} -p tcp --dport 3306 -j DNAT --to-destination 192.168.20.1:9998')

def apply_state_2(ip):
    log(f'STATE 2 — {ip} — routing to challenge gate')
    run_cmd(f'iptables -t nat -D PREROUTING -s {ip} -p tcp --dport 22 -j DNAT --to-destination 192.168.20.1:9999 2>/dev/null')
    run_cmd(f'iptables -t nat -D PREROUTING -s {ip} -p tcp --dport 3306 -j DNAT --to-destination 192.168.20.1:9998 2>/dev/null')
    run_cmd(f'iptables -t nat -A PREROUTING -s {ip} -p tcp --dport 80 -j DNAT --to-destination {CHALLENGE_GATE}')

def apply_state_3(ip):
    log(f'STATE 3 — {ip} — redirecting to maze')
    run_cmd(f'iptables -t nat -D PREROUTING -s {ip} -p tcp --dport 80 -j DNAT --to-destination {CHALLENGE_GATE} 2>/dev/null')
    run_cmd(f'iptables -t nat -A PREROUTING -s {ip} -p tcp --dport 80 -j DNAT --to-destination {DECEPTION_VM}:80')
    log(f'STATE 3 — {ip} — NOW INSIDE THE MAZE')

def get_ip_state(ip):
    with state_lock:
        if ip not in ip_state:
            ip_state[ip] = {
                'conditions': set(),
                'state': 0,
                'first_seen': datetime.now(),
                'last_seen': datetime.now()
            }
        return ip_state[ip]

def is_expired(state):
    return datetime.now() - state['last_seen'] > timedelta(hours=CONDITION_WINDOW_HOURS)

def process_alert(line):
    if 'SHADOWTIER' not in line:
        return

    sid_match = re.search(r'\[1:(\d+):\d+\]', line)
    ip_match = re.search(r'\{TCP\}\s+(\d+\.\d+\.\d+\.\d+):\d+\s+->', line)

    if not sid_match or not ip_match:
        return

    sid = sid_match.group(1)
    ip = ip_match.group(1)

    if sid not in SHADOWTIER_SIDS:
        return

    condition = SHADOWTIER_SIDS[sid]

    with state_lock:
        state = get_ip_state(ip)

        if is_expired(state):
            log(f'RESET — {ip} — window expired, starting fresh')
            ip_state[ip] = {
                'conditions': set(),
                'state': 0,
                'first_seen': datetime.now(),
                'last_seen': datetime.now()
            }
            state = ip_state[ip]

        state['last_seen'] = datetime.now()

        if condition not in state['conditions']:
            state['conditions'].add(condition)
            count = len(state['conditions'])
            log(f'CONDITION {count}/3 — {ip} — triggered: {condition}')

            if count == 1 and state['state'] < 1:
                state['state'] = 1
                apply_state_1(ip)

            elif count == 2 and state['state'] < 2:
                state['state'] = 2
                apply_state_2(ip)

            elif count >= 3 and state['state'] < 3:
                state['state'] = 3
                apply_state_3(ip)

def cleanup_thread():
    while True:
        time.sleep(3600)
        with state_lock:
            expired = [ip for ip, state in ip_state.items() if is_expired(state)]
            for ip in expired:
                log(f'CLEANUP — removing expired entry for {ip}')
                del ip_state[ip]

def main():
    log('Shadow Tier Commander v2 starting')
    log(f'Watching: {LOG_FILE}')
    log('States: 1=Layer Zero intensify | 2=Challenge gate | 3=Maze redirect')

    cleaner = threading.Thread(target=cleanup_thread, daemon=True)
    cleaner.start()

    with open(LOG_FILE, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue
            process_alert(line)

if __name__ == '__main__':
    main()
