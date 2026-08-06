import socket
import threading
import json
import time
import subprocess
import logging
from datetime import datetime

GATE_HOST = '127.0.0.1'
GATE_PORT = 8080
DECEPTION_VM = '192.168.30.2'
RETRY_WINDOW = 47
MAX_REQUESTS_PER_WINDOW = 3
WINDOW_SECONDS = 30
TARPIT_DELAY = 9

logging.basicConfig(
    filename='/opt/shadowtier/logs/challenge.log',
    level=logging.INFO,
    format='[%(asctime)s] %(message)s'
)

challenge_state = {}
state_lock = threading.Lock()

def log(msg):
    logging.info(msg)
    print(f'[CHALLENGE] {msg}')

def redirect_to_maze(ip):
    log(f'ESCALATING {ip} to maze — challenge failed')
    cmd = f'iptables -t nat -A PREROUTING -s {ip} -p tcp --dport 80 -j DNAT --to-destination {DECEPTION_VM}:80'
    subprocess.run(cmd, shell=True)

def get_state(ip):
    with state_lock:
        if ip not in challenge_state:
            challenge_state[ip] = {
                'phase': 'maintenance',
                'first_contact': time.time(),
                'retry_after': time.time() + RETRY_WINDOW,
                'request_count': 0,
                'window_start': time.time(),
                'escalated': False
            }
        return challenge_state[ip]

def check_rate(ip, state):
    now = time.time()
    if now - state['window_start'] > WINDOW_SECONDS:
        state['window_start'] = now
        state['request_count'] = 1
        return False
    state['request_count'] += 1
    if state['request_count'] > MAX_REQUESTS_PER_WINDOW:
        log(f'RATE EXCEEDED for {ip} — {state["request_count"]} requests in {WINDOW_SECONDS}s')
        return True
    return False

def handle_client(conn, addr):
    ip = addr[0]
    log(f'Connection from {ip}')

    try:
        data = conn.recv(4096).decode('utf-8', errors='ignore')
        if not data:
            conn.close()
            return

        time.sleep(TARPIT_DELAY)

        state = get_state(ip)

        if state['escalated']:
            conn.close()
            return

        if check_rate(ip, state):
            if not state['escalated']:
                state['escalated'] = True
                redirect_to_maze(ip)
            conn.close()
            return

        now = time.time()

        if state['phase'] == 'maintenance':
            if now < state['retry_after']:
                seconds_remaining = int(state['retry_after'] - now)
                log(f'{ip} hit gate early — {seconds_remaining}s remaining')
                response_body = json.dumps({
                    'status': 'service_unavailable',
                    'message': 'This service is temporarily undergoing maintenance.',
                    'retry_after': seconds_remaining,
                    'incident_id': 'INC-2026-0718'
                })
                http_response = (
                    'HTTP/1.1 503 Service Unavailable\r\n'
                    'Content-Type: application/json\r\n'
                    f'Retry-After: {seconds_remaining}\r\n'
                    f'Content-Length: {len(response_body)}\r\n'
                    'Connection: close\r\n\r\n'
                    + response_body
                )
                conn.send(http_response.encode())

                if seconds_remaining > RETRY_WINDOW - 5:
                    state['escalated'] = True
                    redirect_to_maze(ip)

            else:
                log(f'{ip} passed maintenance gate — issuing OTP challenge')
                state['phase'] = 'otp'
                response_body = json.dumps({
                    'status': 'verification_required',
                    'message': 'Unusual activity detected on your account. Please enter the OTP sent to your registered device.',
                    'session_id': f'SESS-{int(now)}-VERIFY',
                    'expires_in': 300
                })
                http_response = (
                    'HTTP/1.1 200 OK\r\n'
                    'Content-Type: application/json\r\n'
                    f'Content-Length: {len(response_body)}\r\n'
                    'Connection: close\r\n\r\n'
                    + response_body
                )
                conn.send(http_response.encode())

        elif state['phase'] == 'otp':
            if 'otp' in data.lower() or 'token' in data.lower() or 'code' in data.lower():
                log(f'{ip} submitted OTP response — passing to real server')
                response_body = json.dumps({
                    'status': 'success',
                    'message': 'Verification complete. Redirecting...'
                })
                http_response = (
                    'HTTP/1.1 200 OK\r\n'
                    'Content-Type: application/json\r\n'
                    f'Content-Length: {len(response_body)}\r\n'
                    'Connection: close\r\n\r\n'
                    + response_body
                )
                conn.send(http_response.encode())
                state['escalated'] = True
            else:
                log(f'{ip} failed OTP phase — escalating to maze')
                state['escalated'] = True
                redirect_to_maze(ip)
                conn.close()
                return

    except Exception as e:
        log(f'Error handling {ip}: {e}')
    finally:
        conn.close()

def start_gate():
    sudo_mkdir = 'sudo mkdir -p /opt/shadowtier/logs'
    subprocess.run(sudo_mkdir, shell=True)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((GATE_HOST, GATE_PORT))
    server.listen(100)
    log(f'Shadow Tier Challenge Gate listening on {GATE_HOST}:{GATE_PORT}')

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.daemon = True
        thread.start()

if __name__ == '__main__':
    start_gate()
