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
PROXY_FILE = "proxies.txt"

class UltimateDeltaCLI:
    def __init__(self, proxy=None):
        self.session = requests.Session()
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
            
        self.session.headers.update({
            "User-Agent": UA,
            "Accept": "application/json",
            "Origin": "https://auth.platorelay.com",
            "Referer": "https://auth.platorelay.com/"
        })
        self.sentry_public_key = None
        self.final_ticket = None
        self.final_key = None

    def load_token(self):
        if os.path.exists(TOKEN_FILE):
            try:
                with open(TOKEN_FILE, "r") as f:
                    data = json.load(f)
                    if time.time() < data.get("expires_at", 0):
                        return data.get("token")
            except Exception:
                pass
        return None

    def save_token(self, token, expires_in):
        try:
            with open(TOKEN_FILE, "w") as f:
                json.dump({
                    "token": token,
                    "expires_at": time.time() + expires_in - 60
                }, f)
        except Exception:
            pass

    def upload_to_host(self, file_path):
        try:
            url = "https://0x0.st"
            with open(file_path, 'rb') as f:
                files = {'file': f}
                r = requests.post(url, files=files, timeout=30)
                if r.status_code == 200:
                    return r.text.strip()
        except: pass
        return None

    def encrypt_aes_ctr(self, data_str, key_bytes, iv_bytes):
        try:
            iv_int = int.from_bytes(iv_bytes, byteorder='big')
            ctr = Counter.new(128, initial_value=iv_int)
            cipher = AES.new(key_bytes, AES.MODE_CTR, counter=ctr)
            encrypted_bytes = cipher.encrypt(data_str.encode('utf-8'))
            return binascii.hexlify(encrypted_bytes).decode('utf-8')
        except Exception: return "empty"

    def do_auth_step(self, ticket):
        print(f"\n[*] Authenticating Platorelay (Ticket: {ticket[:10]}...).")
        meta_key = ticket[0:16].encode('ascii')
        meta_iv  = ticket[16:32].encode('ascii')
        stream_key = ticket[1:17].encode('ascii')
        stream_iv  = ticket[17:33].encode('ascii')

        meta_json = json.dumps({"browserInfo": {"userAgent": UA,"language": "en-US","platform": "Linux armv8l","screen": {"width": 412, "height": 915},"devicePixelRatio": 3,"hardwareConcurrency": 8,"deviceMemory": 8,"maxTouchPoints": 5}}, separators=(',', ':'))
        stream_json = json.dumps([{"name": "performance", "data": int(time.time() * 1000)},{"name": "history", "data": {"length": 2}},{"name": "webdriver", "webdriver": False},{"name": "connection", "data": {"effectiveType": "4g", "rtt": 50}}], separators=(',', ':'))

        payload = {
            "ticket": ticket, "service": 2, "captcha": None,
            "meta": self.encrypt_aes_ctr(meta_json, meta_key, meta_iv),
            "stream": self.encrypt_aes_ctr(stream_json, stream_key, stream_iv),
            "resolved": True
        }

        try:
            r = self.session.put(f"https://auth.platorelay.com/api/session/step?ticket={ticket}&service=2", json=payload, timeout=10)
            if r.status_code == 200:
                data = r.json()
                link = None
                raw_data = data.get('data')
                if isinstance(raw_data, dict): link = raw_data.get('url')
                elif isinstance(raw_data, str): link = raw_data
                if not link: link = data.get('redirectUrl')
                print(f"  [+] Target URL obtained: {link}")
                return link
        except Exception as e:
            print(f"  [-] Auth Error: {e}")
        return None

    def encrypt_hybrid_sentry(self, payload_dict):
        der_data = base64.b64decode(self.sentry_public_key)
        public_key = load_der_public_key(der_data)
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        payload_bytes = json.dumps(payload_dict, separators=(',', ':')).encode('utf-8')
        aes_ciphertext = aesgcm.encrypt(iv, payload_bytes, None)

        enc_aes_key = public_key.encrypt(
            aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        rsa_length_prefix = len(enc_aes_key).to_bytes(2, byteorder='big')
        packed_data = rsa_length_prefix + enc_aes_key + iv + aes_ciphertext
        return base64.b64encode(packed_data).decode('utf-8')

    def generate_telemetry(self):
        return {
            "dwellMs": random.randint(5000, 8000), "moves": random.randint(50, 90), "velocityVar": 0.499423691542776,
            "velocityMedian": 0.6251680437154814, "velocityAvg": 0.8782068044703519,
            "velocityMin": 0.013410846751506588, "velocityMax": 3.7751796788938536,
            "velocityP25": 0.49378509640492646, "velocityP75": 1.0795063822287094,
            "directionChanges": random.randint(1, 5), "keypresses": 0, "speedSamples": random.randint(50, 90), "moveDensity": 96.98550724637681
        }

    def do_sentry_step(self, sentry_url):
        print("\n[*] Analyzing Sentry barrier.")
        
        saved_token = self.load_token()
        if saved_token:
            print("  [+] Cached JWT Token found. Attempting bypass.")
            self.session.cookies.set("_gs_pow_token", saved_token, domain="sentry.platorelay.com")
            r_check = self.session.get(sentry_url, allow_redirects=False)
            if r_check.status_code == 302:
                final_link = r_check.headers.get("Location")
                print("  [+] Sentry bypassed via Token.")
                return final_link

        r_html = self.session.get(sentry_url, timeout=10)
        match = re.search(r'window\.__GSK\s*=\s*["\']([^"\']+)["\']', r_html.text)
        if match: self.sentry_public_key = match.group(1)
        else: return None

        sentry_headers = {"Origin": "https://sentry.platorelay.com", "Referer": sentry_url, "Content-Type": "text/plain"}
        device_fp = "-238d70b6"

        req_payload = {"telemetry": self.generate_telemetry(), "deviceFingerprint": device_fp, "forcePuzzle": False}
        r_req = self.session.post("https://sentry.platorelay.com/.gs/pow/captcha/request", data=self.encrypt_hybrid_sentry(req_payload), headers=sentry_headers, timeout=10)
        if r_req.status_code != 200: return None
            
        captcha_data = r_req.json().get("data", {})
        c_id = captcha_data.get("id")
        instruction = captcha_data['stages'][0]['instruction']
        shapes = captcha_data['stages'][0]['shapes']
        
        print(f"\n[?] CAPTCHA INSTRUCTION: {instruction}")
        
        images = []
        for shape in shapes:
            images.append(Image.open(io.BytesIO(base64.b64decode(shape['img']))))
            
        if images:
            w, h = images[0].size
            cols = 3
            rows = (len(images) + cols - 1) // cols
            padding = 10
            grid_img = Image.new('RGB', (cols * w + (cols + 1) * padding, rows * h + (rows + 1) * padding), color=(25, 25, 30))
            draw = ImageDraw.Draw(grid_img)
            try: font = ImageFont.truetype("arial.ttf", 24)
            except: font = ImageFont.load_default()
            for i, img in enumerate(images):
                row, col = i // cols, i % cols
                x, y = padding + col * (w + padding), padding + row * (h + padding)
                grid_img.paste(img, (x, y))
                text, tx, ty = str(i + 1), x + 8, y + 8
                for dx, dy in [(-2,0), (2,0), (0,-2), (0,2)]: draw.text((tx+dx, ty+dy), text, font=font, fill="black")
                draw.text((tx, ty), text, font=font, fill="white")
            grid_img.save("captcha_grid.png")
            
            print("  [*] Uploading captcha grid to 0x0.st...")
            image_url = self.upload_to_host("captcha_grid.png")
            if image_url:
                print(f"  [!] CAPTCHA IMAGE LINK: {image_url}")
            else:
                print("  [-] Upload failed. Check 'captcha_grid.png' manually.")

        start_solve_time = time.time()
        user_input = input(f"\n[>] Select correct image index (1-{len(images)}): ")
        user_ans = str(int(user_input) - 1) 
        solve_time_ms = int((time.time() - start_solve_time) * 1000) + random.randint(500, 1500)

        dynamic_path = {"moves": random.randint(15, 60), "totalDist": random.randint(150, 500), "durationMs": random.randint(80, 250), "avgSpeed": random.uniform(0.5, 2.5), "clickTimestamp": solve_time_ms, "timeToFirstClick": solve_time_ms}
        verify_payload = {"id": c_id, "answers": [user_ans], "path": dynamic_path, "telemetry": self.generate_telemetry(), "deviceFingerprint": device_fp}
        r_verify = self.session.post("https://sentry.platorelay.com/.gs/pow/captcha/verify", data=self.encrypt_hybrid_sentry(verify_payload), headers=sentry_headers, timeout=10)
        
        if r_verify.status_code == 200 and r_verify.json().get("success"):
            print("  [+] Verification successful.")
            token = r_verify.json()["data"]["token"]
            expires_in = r_verify.json()["data"].get("expiresIn", 3599)
            self.save_token(token, expires_in)
            self.session.cookies.set("_gs_pow_token", token, domain="sentry.platorelay.com")
            r_final = self.session.get(sentry_url, allow_redirects=False)
            if r_final.status_code == 302:
                if os.path.exists("captcha_grid.png"): os.remove("captcha_grid.png")
                return r_final.headers.get("Location")
        return None

    def decode_uri(self, encoded_string, prefix_length=5):
        try:
            missing_padding = len(encoded_string) % 4
            if missing_padding: encoded_string += '=' * (4 - missing_padding)
            decoded_bytes = base64.b64decode(encoded_string)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            prefix, encoded_portion, result = decoded_str[:prefix_length], decoded_str[prefix_length:], ""
            for i in range(len(encoded_portion)):
                result += chr(ord(encoded_portion[i]) ^ ord(prefix[i % len(prefix)]))
            return result
        except: return None

    def do_lootlink_bypass(self, loot_url):
        print(f"\n[*] Processing Loot-Link: {loot_url}")
        try:
            self.session.headers.update({"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"})
            r = self.session.get(loot_url, timeout=10)
            html = r.text
            tid_match = re.search(r'tid["\']?\s*[:=]\s*["\']?([0-9]+)', html)
            matches = re.findall(r'[\'"]([0-9]{17,21})[\'"]', html)
            if not matches: return None
            tid, sess, rkey = tid_match.group(1) if tid_match else "1015561", matches[0], (matches[1] if len(matches) > 1 and matches[1] != matches[0] else matches[0])
            payload = {"tid": int(tid), "bl": [10], "session": sess, "cur_url": loot_url, "rkey": rkey, "is_loot": False, "botd": "{\"bot\":false}", "offer": "0"}
            r_tc = self.session.post("https://nerventualken.com/tc", json=payload, timeout=10)
            tasks = r_tc.json()
            if not tasks: return None
            urids, cats, task_data, max_wait = [], [], [], 0
            for t in tasks:
                u, c, w = str(t.get('urid', '')), str(t.get('cat', '54')), int(t.get('time_to_complete', 15000))
                if w > max_wait: max_wait = w
                if u:
                    urids.append(u); cats.append(c)
                    task_data.append({'urid': u, 'cat': c, 'tid': tid, 'pixel': t.get('action_pixel_url')})
            sub = int(urids[0][-5:]) % 3
            for t in task_data: self.session.get(f"https://{sub}.onsultingco.com/st?uid={t['urid']}&cat={t['cat']}", timeout=2)
            ws_url = f"wss://{sub}.onsultingco.com/c?uid={','.join(urids)}&cat={','.join(cats)}&key={rkey}&session_id={sess}&is_loot=0&tid={tid}"
            wait_sec = (max_wait / 1000.0) + 0.5
            print(f"  [+] Waiting {wait_sec}s for server validation.")
            def completion_ping():
                time.sleep(wait_sec)
                for t in task_data: self.session.get(f"https://nerventualken.com/td?ac=1&urid={t['urid']}&cat={t['cat']}&tid={t['tid']}", timeout=2)
            threading.Thread(target=completion_ping, daemon=True).start()
            def on_message(ws, message):
                if "r:" in message:
                    decoded = self.decode_uri(message.replace("r:", ""))
                    if decoded and "d=" in decoded:
                        self.final_ticket = decoded.split("d=")[1].split("&")[0]
                        ws.close()
            ws = websocket.WebSocketApp(ws_url, header={"Origin": "https://loot-link.com", "User-Agent": UA}, on_message=on_message)
            ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
            return self.final_ticket
        except: return None

    def get_final_key(self, final_ticket):
        print("\n[*] Requesting Final Key.")
        self.do_auth_step(final_ticket)
        for _ in range(10):
            try:
                status_r = self.session.get(f"https://auth.platorelay.com/api/session/status?ticket={final_ticket}", timeout=5)
                key = status_r.json().get('data', {}).get('key')
                if key: return key
            except: pass
            time.sleep(1)
        return None

    def run(self, raw_input):
        ticket = ''.join(c for c in (raw_input.split("ticket=")[1].split("&")[0] if "ticket=" in raw_input else (raw_input.split("d=")[1].split("&")[0] if "d=" in raw_input else raw_input)) if c in string.ascii_letters + string.digits + "-_.")
        link = self.do_auth_step(ticket)
        if not link: return print("[-] Invalid Ticket.")
        if "sentry.platorelay.com" in link:
            link = self.do_sentry_step(link)
            if not link: return print("[-] Sentry failed.")
        final_ticket = self.do_lootlink_bypass(link)
        if final_ticket:
            key = self.get_final_key(final_ticket)
            if key: print(f"\n[+] FINAL KEY: {key}\n")
        else: print("\n[-] Bypass failed.")

if __name__ == '__main__':
    print("="*60 + "\n DELTA CLI - DYNAMIC GRID & 0X0.ST IMAGE HOST\n" + "="*60)
    selected_proxy = None
    if os.path.exists(PROXY_FILE):
        with open(PROXY_FILE, "r") as f:
            proxies = [l.strip() for l in f if l.strip()]
            if proxies:
                selected_proxy = random.choice(proxies)
                print(f"[*] Proxy: {selected_proxy}")
    while True:
        target = input("[>] Enter Ticket/URL (or 'q'): ")
        if target.lower() in ['q', 'exit']: break
        start = time.time()
        UltimateDeltaCLI(proxy=selected_proxy).run(target)
        print(f"[*] Done in {time.time() - start:.2f}s\n")
