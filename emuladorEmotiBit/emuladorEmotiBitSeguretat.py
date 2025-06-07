#!/usr/bin/env python3
"""
EmotiBit Emulator – robust handshake, auto-reconnect,
AES-256-ECB + HMAC-SHA256 data encryption via PyCryptodome,
and decryption of incoming control & data packets.
Sends data in 512-byte max encrypted UDP packets.
"""

import socket
import threading
import time
import random
import datetime
import sys
import hmac
import hashlib
from Crypto.Cipher import AES

# ── CONFIG ─────────────────────────────────────────────────────────────
CTRL_PORT         = 3131
DATA_PORT         = 3132
LSL_PORT          = 16571
DEVICE_ID         = "MD-V5-00001448"

FRAME_INTERVAL    = 0.05
LSL_INTERVAL      = 1.0
KEEPALIVE_INT     = 0.5
KEEPALIVE_TIMEOUT = 2

# AES-256 + HMAC-SHA256
PSK              = b"2475ee103f0525bb5fcf615f8c1d8258"  # 32 bytes
PSK_E              = b"0e3ec16df8c53b850c86c4e706054e36"  # 32 bytes
BLOCK_SIZE       = 16
HMAC_LEN         = 32
MAX_TOTAL_PACKET = 512
MAX_PLAINTEXT    = MAX_TOTAL_PACKET - HMAC_LEN - BLOCK_SIZE  # 464 bytes

# ── GLOBAL STATE ────────────────────────────────────────────────────────
seq        = 50000
tick       = 6600
state      = "WAIT_HE"
osc_ip     = None
osc_pt     = None
data_dp    = None
ka_counter = 0
last_pn    = time.time()

# ── SOCKET SETUP ────────────────────────────────────────────────────────
ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ctrl_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ctrl_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
ctrl_sock.bind(("0.0.0.0", CTRL_PORT))
ctrl_sock.settimeout(0.5)

data_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
data_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
data_sock.bind(("0.0.0.0", DATA_PORT))

lsl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
lsl_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

def log(tag, addr, msg):
    print(f"{tag} {addr}: {msg.strip()}")

# ── CRYPTO ───────────────────────────────────────────────────────────────
def encrypt_and_hmac_eb(raw: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(raw) % BLOCK_SIZE)
    raw += bytes([pad_len]) * pad_len
    cipher = AES.new(PSK_E, AES.MODE_ECB)
    ct = cipher.encrypt(raw)
    mac = hmac.new(PSK_E, ct, hashlib.sha256).digest()
    return ct + mac
def encrypt_and_hmac(raw: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(raw) % BLOCK_SIZE)
    raw += bytes([pad_len]) * pad_len
    cipher = AES.new(PSK, AES.MODE_ECB)
    ct = cipher.encrypt(raw)
    mac = hmac.new(PSK_E, ct, hashlib.sha256).digest()
    return ct + mac

def decrypt_and_verify(pkt: bytes) -> bytes:
    if len(pkt) < HMAC_LEN:
        raise ValueError("Packet too short for HMAC")
    ct, recv_mac = pkt[:-HMAC_LEN], pkt[-HMAC_LEN:]
    exp_mac = hmac.new(PSK, ct, hashlib.sha256).digest()
    if recv_mac != exp_mac:
        raise ValueError("Invalid HMAC")
    cipher = AES.new(PSK, AES.MODE_ECB)
    pt = cipher.decrypt(ct)
    pad = pt[-1]
    if pad < 1 or pad > BLOCK_SIZE:
        raise ValueError("Bad padding")
    return pt[:-pad]

# ── FRAME GENERATOR ─────────────────────────────────────────────────────
def make_frame_lines():
    global seq, tick
    lines = []
    def add(code, vals):
        nonlocal lines
        global seq, tick
        chan = vals.count(",") + 1 if "," in vals else 1
        lines.append(f"{seq},{tick},{chan},{code},1,100,{vals}")
        seq += 1; tick += 1

    add("DC", "2,100,EA,1,EL,1")
    add("PI", f"{random.uniform(49370,49480):.6f}")
    add("PR", f"{random.uniform(35200,35350):.6f}")
    add("PG", f"{random.uniform(3020,3070):.6f}")
    add("EA", "0.035")
    add("EL", f"{random.uniform(25000,27000):.6f}")
    add("T1", "30")
    add("TH", "29.5")
    for axis in ["AX","AY","AZ","GX","GY","GZ"]:
        add(axis, ",".join(f"{random.uniform(0,0.05):.6f}" for _ in range(3)))
    add("MX", "-30,-31,-31")
    add("MY", "-9,-10,-10")
    add("MZ", "0,0,0")
    add("EM", "RS,RE,PS,MN")
    return lines

# ── FRAGMENTED SENDER ───────────────────────────────────────────────────
def send_fragmented(raw: bytes):
    offset = 0
    while offset < len(raw):
        end = min(offset + MAX_PLAINTEXT, len(raw))
        newline = raw.rfind(b'\n', offset, end)
        if newline == -1 or newline <= offset:
            newline = end
        chunk = raw[offset: newline + 1]
        packet = encrypt_and_hmac_eb(chunk)
        if len(packet) <= MAX_TOTAL_PACKET:
            data_sock.sendto(packet, (osc_ip, data_dp))
            log("TX", (osc_ip, data_dp), f"[{len(packet)} bytes]")
        else:
            log("!!", (osc_ip, data_dp), f"Oversized fragment: {len(packet)}")
        offset = newline + 1

# ── LSL BEACONS ──────────────────────────────────────────────────────────
def lsl_beacons():
    tick_lsl = 16572
    header = "LSL:shortinfo\r\nsession_id='default'\r\n"
    targets = [
        ("255.255.255.255", LSL_PORT),
        ("224.0.0.183",      LSL_PORT),
        ("239.255.172.215",  LSL_PORT)
    ]
    while state != "CONNECTED":
        pkt = (header + f"{tick_lsl} 0\r\n").encode()
        for dst in targets:
            lsl_sock.sendto(pkt, dst); log("TX", dst, "LSL beacon")
        tick_lsl += 1
        time.sleep(LSL_INTERVAL)

# ── CONTROL LOOP ─────────────────────────────────────────────────────────
def control_loop():
    global state, osc_ip, osc_pt, data_dp, seq, last_pn
    while True:
        try:
            raw_pkt, addr = ctrl_sock.recvfrom(2048)
        except socket.timeout:
            if state=="CONNECTED" and time.time()-last_pn>KEEPALIVE_TIMEOUT:
                log("!!",(None,None),"No PN received: disconnecting")
                state="WAIT_HE"; data_dp=None
            continue

        try:
            plain = decrypt_and_verify(raw_pkt)
            msg = plain.decode("ascii","ignore").strip()
        except Exception as e:
            log("!!", addr, f"Control decrypt error: {e}")
            continue

        parts = msg.split(",")
        if len(parts) < 4:
            continue

        code = parts[3]
        log("RX", addr, msg)

        if code == "HE" and state != "CONNECTED":
            osc_ip, osc_pt = addr; data_dp = None
            hh_txt = f"{seq},0,0,HH,1,100,DP,-1,DI,{DEVICE_ID}\n"
            hh_pkt = encrypt_and_hmac(hh_txt.encode())
            ctrl_sock.sendto(hh_pkt, addr)
            log("TX", addr, hh_txt)
            seq += 1; state = "WAIT_EC"

        elif code == "EC" and state == "WAIT_EC":
            osc_ip, osc_pt = addr
            try:
                i = parts.index("DP"); data_dp = int(parts[i+1])
            except:
                data_dp = DATA_PORT
            po_txt = f"{seq},1,2,PO,1,100,DP,{data_dp}\n"
            pn_txt = f"{seq+1},1,2,PN,1,100,DP,{data_dp}\n"
            hh2_txt = f"{seq+2},0,0,HH,1,100,DP,{data_dp},DI,{DEVICE_ID}\n"
            for txt in (po_txt, pn_txt, hh2_txt):
                pkt = encrypt_and_hmac(txt.encode())
                ctrl_sock.sendto(pkt, addr)
                log("TX", addr, txt)
            seq += 3; state = "CONNECTED"; last_pn = time.time()

        elif code == "PN" and state == "CONNECTED":
            last_pn = time.time()
            po_txt = f"{seq},1,2,PO,1,100,DP,{data_dp}\n"
            pkt = encrypt_and_hmac(po_txt.encode())
            ctrl_sock.sendto(pkt, addr)
            log("TX", addr, po_txt)
            seq += 1

# ── DATA LOOP ────────────────────────────────────────────────────────────
def data_loop():
    global seq, tick, ka_counter
    last_ka = time.time()
    while True:
        if state=="CONNECTED" and osc_ip and data_dp:
            lines = make_frame_lines()
            raw = ("\n".join(lines) + "\n").encode()
            send_fragmented(raw)

            if time.time()-last_ka>=KEEPALIVE_INT:
                ts = datetime.datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S-%f")[:-3]
                tl = f"{seq},{tick},1,TL,1,100,{ts}\n"; seq+=1; tick+=1
                ak = f"{seq},{tick},2,AK,1,100,{ka_counter},RD\n"; seq+=1; tick+=1; ka_counter+=1
                for msg in (tl, ak):
                    send_fragmented(msg.encode())
                last_ka = time.time()

            time.sleep(FRAME_INTERVAL)
        else:
            time.sleep(0.1)

# ── MAIN ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("🟢 EmuBit – ctrl:3131, data:3132 (AES-256 + HMAC-SHA256)")
    threading.Thread(target=lsl_beacons, daemon=True).start()
    threading.Thread(target=control_loop, daemon=True).start()
    threading.Thread(target=data_loop, daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Emulator stopped.")
        sys.exit(0)
