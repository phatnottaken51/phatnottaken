import requests
import json
import time
import base64
import os
import string
import binascii
import re
import io
import urllib.parse
import ssl
import threading
import random
import websocket
import subprocess

from PIL import Image, ImageDraw, ImageFont
from Crypto.Cipher import AES
from Crypto.Util import Counter
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

UA = "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36"
TOKEN_FILE = "sentry_token.json"

class UltimateDeltaCLI:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": UA,
            "Accept": "application/json",
            "Origin": "https://auth.platorelay.com",
            "Referer": "https://auth.platorelay.com/"
        })
        self.sentry_public_key = None
        self.final_ticket = None
        self.final_key = None
        self.tunnel_url = None

    def start_tunnel_services(self):
        port = random.randint(10000, 20000)
        subprocess.Popen(["python3", "-m", "http.server", str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        proc = subprocess.Popen(["cloudflared", "tunnel", "--url", f"http://localhost:{port}"], stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True)
        
        print(f"[*] Starting Cloudflare Tunnel on port {port}...")
        for _ in range(30):
            line = proc.stderr.readline()
            if "trycloudflare.com" in line:
                match = re.search(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com', line)
                if match:
                    self.tunnel_url = match.group(0)
                    print(f"  [+] Tunnel active: {self.tunnel_url}/captcha_grid.png")
                    break
            time.sleep(0.5)

    def load_token(self):
        if os.path.exists(TOKEN_FILE):
            try:
                with open(TOKEN_FILE, "r") as f:
                    data = json.load(f)
                    if time.time() < data.get("expires_at", 0):
                        return data.get("token")
            except Exception: pass
        return None

    def save_token(self, token, expires_in):
        try:
            with open(TOKEN_FILE, "w") as f:
                json.dump({"token": token, "expires_at": time.time() + expires_in - 60}, f)
        except Exception: pass

    def encrypt_aes_ctr(self, data_str, key_bytes, iv_bytes):
        try:
            iv_int = int.from_bytes(iv_bytes, byteorder='big')
            ctr = Counter.new(128, initial_value=iv_int)
            cipher = AES.new(key_bytes, AES.MODE_CTR, counter=ctr)
            return binascii.hexlify(cipher.encrypt(data_str.encode('utf-8'))).decode('utf-8')
        except Exception: return "empty"

    def do_auth_step(self, ticket):
        print(f"\n[*] Authenticating Platorelay (Ticket: {ticket[:10]}...).")
        meta_key, meta_iv = ticket[0:16].encode('ascii'), ticket[16:32].encode('ascii')
        stream_key, stream_iv = ticket[1:17].encode('ascii'), ticket[17:33].encode('ascii')

        meta_json = json.dumps({"browserInfo": {"userAgent": UA,"language": "en-US","platform": "Linux armv8l","screen": {"width": 412, "height": 915},"devicePixelRatio": 3,"hardwareConcurrency": 8,"deviceMemory": 8,"maxTouchPoints": 5}}, separators=(',', ':'))
        stream_json = json.dumps([{"name": "performance", "data": int(time.time() * 1000)},{"name": "history", "data": {"length": 2}},{"name": "webdriver", "webdriver": False},{"name": "connection", "data": {"effectiveType": "4g", "rtt": 50}}], separators=(',', ':'))

        payload = {"ticket": ticket, "service": 2, "captcha": None, "meta": self.encrypt_aes_ctr(meta_json, meta_key, meta_iv), "stream": self.encrypt_aes_ctr(stream_json, stream_key, stream_iv), "resolved": True}

        try:
            r = self.session.put(f"https://auth.platorelay.com/api/session/step?ticket={ticket}&service=2", json=payload, timeout=10)
            if r.status_code == 200:
                data = r.json()
                raw_data = data.get('data')
                link = (raw_data.get('url') if isinstance(raw_data, dict) else raw_data) or data.get('redirectUrl')
                print(f"  [+] Target URL obtained: {link}")
                return link
        except Exception as e: print(f"  [-] Auth Error: {e}")
        return None

    def encrypt_hybrid_sentry(self, payload_dict):
        der_data = base64.b64decode(self.sentry_public_key)
        public_key = load_der_public_key(der_data)
        aes_key, iv = os.urandom(32), os.urandom(12)
        aes_ciphertext = AESGCM(aes_key).encrypt(iv, json.dumps(payload_dict, separators=(',', ':')).encode('utf-8'), None)
        enc_aes_key = public_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        packed_data = len(enc_aes_key).to_bytes(2, byteorder='big') + enc_aes_key + iv + aes_ciphertext
        return base64.b64encode(packed_data).decode('utf-8')

    def do_sentry_step(self, sentry_url):
        print("\n[*] Analyzing Sentry barrier.")
        saved_token = self.load_token()
        if saved_token:
            self.session.cookies.set("_gs_pow_token", saved_token, domain="sentry.platorelay.com")
            r_check = self.session.get(sentry_url, allow_redirects=False)
            if r_check.status_code == 302:
                print("  [+] Sentry bypassed via Token.")
                return r_check.headers.get("Location")

        r_html = self.session.get(sentry_url, timeout=10)
        match = re.search(r'window\.__GSK\s*=\s*["\']([^"\']+)["\']', r_html.text)
        if match: self.sentry_public_key = match.group(1)
        else: return None

        req_payload = {"telemetry": {"dwellMs": 6000, "moves": 50, "velocityVar": 0.5, "velocityMedian": 0.6, "velocityAvg": 0.8, "velocityMin": 0.01, "velocityMax": 3.0, "velocityP25": 0.4, "velocityP75": 1.0, "directionChanges": 2, "keypresses": 0, "speedSamples": 50, "moveDensity": 90.0}, "deviceFingerprint": "-238d70b6", "forcePuzzle": False}
        r_req = self.session.post("https://sentry.platorelay.com/.gs/pow/captcha/request", data=self.encrypt_hybrid_sentry(req_payload), headers={"Origin": "https://sentry.platorelay.com", "Content-Type": "text/plain"}, timeout=10)
        if r_req.status_code != 200: return None
            
        captcha_data = r_req.json().get("data", {})
        c_id, instruction, shapes = captcha_data.get("id"), captcha_data['stages'][0]['instruction'], captcha_data['stages'][0]['shapes']
        
        print(f"\n[?] CAPTCHA INSTRUCTION: {instruction}")
        images = [Image.open(io.BytesIO(base64.b64decode(s['img']))) for s in shapes]
        
        if images:
            w, h, cols = images[0].size, 3
            rows = (len(images) + cols - 1) // cols
            grid_img = Image.new('RGB', (cols * w + 40, rows * h + 40), color=(25, 25, 30))
            draw = ImageDraw.Draw(grid_img)
            try: font = ImageFont.truetype("arial.ttf", 24)
            except: font = ImageFont.load_default()
            for i, img in enumerate(images):
                row, col = i // cols, i % cols
                x, y = 10 + col * (w + 10), 10 + row * (h + 10)
                grid_img.paste(img, (x, y))
                for dx, dy in [(-2,0), (2,0), (0,-2), (0,2)]: draw.text((x+8+dx, y+8+dy), str(i+1), font=font, fill="black")
                draw.text((x+8, y+8), str(i+1), font=font, fill="white")
            grid_img.save("captcha_grid.png")
            print(f"  [!] REFRESH IMAGE: {self.tunnel_url}/captcha_grid.png")

        start_time = time.time()
        user_input = input(f"\n[>] Select correct image index (1-{len(images)}): ")
        solve_ms = int((time.time() - start_time) * 1000) + 1000

        verify_payload = {"id": c_id, "answers": [str(int(user_input)-1)], "path": {"moves": 30, "totalDist": 300, "durationMs": 200, "avgSpeed": 1.5, "clickTimestamp": solve_ms, "timeToFirstClick": solve_ms}, "telemetry": {"dwellMs": 6000, "moves": 50, "velocityVar": 0.5, "velocityMedian": 0.6, "velocityAvg": 0.8, "velocityMin": 0.01, "velocityMax": 3.0, "velocityP25": 0.4, "velocityP75": 1.0, "directionChanges": 2, "keypresses": 0, "speedSamples": 50, "moveDensity": 90.0}, "deviceFingerprint": "-238d70b6"}
        r_verify = self.session.post("https://sentry.platorelay.com/.gs/pow/captcha/verify", data=self.encrypt_hybrid_sentry(verify_payload), headers={"Origin": "https://sentry.platorelay.com", "Content-Type": "text/plain"}, timeout=10)
        
        if r_verify.status_code == 200 and r_verify.json().get("success"):
            print("  [+] Verification successful.")
            data = r_verify.json()["data"]
            self.save_token(data["token"], data.get("expiresIn", 3599))
            self.session.cookies.set("_gs_pow_token", data["token"], domain="sentry.platorelay.com")
            r_final = self.session.get(sentry_url, allow_redirects=False)
            if r_final.status_code == 302: return r_final.headers.get("Location")
        return None

    def decode_uri(self, encoded, prefix_len=5):
        try:
            missing = len(encoded) % 4
            if missing: encoded += '=' * (4 - missing)
            decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
            p, e, res = decoded[:prefix_len], decoded[prefix_len:], ""
            for i in range(len(e)): res += chr(ord(e[i]) ^ ord(p[i % len(p)]))
            return res
        except: return None

    def do_lootlink_bypass(self, loot_url):
        print(f"\n[*] Processing Loot-Link: {loot_url}")
        try:
            r = self.session.get(loot_url, timeout=10)
            tid_match = re.search(r'tid["\']?\s*[:=]\s*["\']?([0-9]+)', r.text)
            matches = re.findall(r'[\'"]([0-9]{17,21})[\'"]', r.text)
            if not matches: return None
            tid, sess, rkey = tid_match.group(1) if tid_match else "1015561", matches[0], (matches[1] if len(matches) > 1 and matches[1] != matches[0] else matches[0])
            r_tc = self.session.post("https://nerventualken.com/tc", json={"tid": int(tid), "bl": [10], "session": sess, "cur_url": loot_url, "rkey": rkey, "is_loot": False, "botd": "{\"bot\":false}", "offer": "0"}, timeout=10)
            tasks = r_tc.json()
            if not tasks: return None
            urids, cats, task_data, max_wait = [], [], [], 0
            for t in tasks:
                u, c, w = str(t.get('urid', '')), str(t.get('cat', '54')), int(t.get('time_to_complete', 15000))
                if w > max_wait: max_wait = w
                if u: urids.append(u); cats.append(c); task_data.append({'urid': u, 'cat': c, 'tid': tid})
            sub = int(urids[0][-5:]) % 3
            for t in task_data: self.session.get(f"https://{sub}.onsultingco.com/st?uid={t['urid']}&cat={t['cat']}", timeout=2)
            wait_sec = (max_wait / 1000.0) + 0.5
            print(f"  [+] Waiting {wait_sec}s for validation.")
            threading.Thread(target=lambda: (time.sleep(wait_sec), [self.session.get(f"https://nerventualken.com/td?ac=1&urid={t['urid']}&cat={t['cat']}&tid={t['tid']}", timeout=2) for t in task_data]), daemon=True).start()
            
            ws_url = f"wss://{sub}.onsultingco.com/c?uid={','.join(urids)}&cat={','.join(cats)}&key={rkey}&session_id={sess}&is_loot=0&tid={tid}"
            def on_message(ws, message):
                if "r:" in message:
                    res = self.decode_uri(message.replace("r:", ""))
                    if res and "d=" in res: self.final_ticket = res.split("d=")[1].split("&")[0]; ws.close()
            websocket.WebSocketApp(ws_url, header={"Origin": "https://loot-link.com", "User-Agent": UA}, on_message=on_message).run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
            return self.final_ticket
        except: return None

    def get_final_key(self, ticket):
        print("\n[*] Requesting Final Key.")
        self.do_auth_step(ticket)
        for _ in range(10):
            try:
                r = self.session.get(f"https://auth.platorelay.com/api/session/status?ticket={ticket}", timeout=5)
                key = r.json().get('data', {}).get('key')
                if key: return key
            except: pass
            time.sleep(1)
        return None

    def run(self, raw):
        ticket = ''.join(c for c in (raw.split("ticket=")[1].split("&")[0] if "ticket=" in raw else (raw.split("d=")[1].split("&")[0] if "d=" in raw else raw)) if c in string.ascii_letters + string.digits + "-_.")
        self.start_tunnel_services()
        link = self.do_auth_step(ticket)
        if not link: return print("[-] Invalid Ticket.")
        if "sentry.platorelay.com" in link:
            link = self.do_sentry_step(link)
            if not link: return print("[-] Sentry failed.")
        final = self.do_lootlink_bypass(link)
        if final:
            key = self.get_final_key(final)
            if key: print(f"\n[+] FINAL KEY: {key}\n")
        else: print("\n[-] Bypass failed.")

if __name__ == '__main__':
    print("="*60 + "\n DELTA CLI - ONE TAB TUNNEL INTEGRATION\n" + "="*60)
    while True:
        target = input("[>] Enter Ticket/URL (or 'q'): ")
        if target.lower() in ['q', 'exit']: break
        UltimateDeltaCLI().run(target)
