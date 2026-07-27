from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import datetime

LOG_FILE = '/opt/deception-server/attacker_log.txt'

def log(msg):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    entry = f'[{timestamp}] {msg}'
    print(entry)
    with open(LOG_FILE, 'a') as f:
        f.write(entry + '\n')

class DeceptionHandler(BaseHTTPRequestHandler):
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
        
        log(f'ATTACKER {self.client_address[0]} POST {self.path} — DATA: {body}')
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        if '/login' in self.path:
            response = json.dumps({
                'status': 'success',
                'token': 'eyJhbGciOiJIUzI1NiJ9.fake.token',
                'message': 'Welcome back. Session established.',
                'session_id': 'SID-7842-ALPHA'
            })
            log(f'DECEPTION: Sent fake login success to {self.client_address[0]}')
            
        elif '/auth' in self.path:
            response = json.dumps({
                'status': 'authenticated',
                'role': 'admin',
                'permissions': ['read', 'write', 'transfer'],
                'expires': '2026-12-31T23:59:59Z'
            })
            log(f'DECEPTION: Sent fake auth token with admin role to {self.client_address[0]}')
            
        elif '/admin' in self.path:
            response = json.dumps({
                'status': 'access_granted',
                'panel': 'admin_dashboard',
                'accounts': 47832,
                'total_balance': '$2,847,392,881.00',
                'message': 'Admin panel loading...'
            })
            log(f'DECEPTION: Sent fake admin panel access to {self.client_address[0]}')
            
        elif '/api' in self.path:
            response = json.dumps({
                'status': 'ok',
                'api_version': 'v2.3.1',
                'endpoints': ['/api/accounts', '/api/transfer', '/api/users'],
                'rate_limit': '1000/hour'
            })
            log(f'DECEPTION: Sent fake API response to {self.client_address[0]}')
            
        else:
            response = json.dumps({
                'status': 'processing',
                'message': 'Request received. One moment...'
            })
            
        self.wfile.write(response.encode())
    
    def do_GET(self):
        log(f'ATTACKER {self.client_address[0]} GET {self.path}')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<html><body><h1>Welcome to SecureBank Portal</h1><p>Please login to continue.</p></body></html>')
    
    def log_message(self, format, *args):
        pass

print('Shadow Tier Deception Server starting on port 80...')
log('Deception server initialized — maze is active')
HTTPServer(('0.0.0.0', 80), DeceptionHandler).serve_forever()
