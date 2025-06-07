from scapy.all import sniff, IP, UDP, Raw

# 🎯 Configuració
INTERFACE = "enp0s3"
FILTER = "udp and src host 192.168.0.102 and src port 16571"

print(f"\n🎧 Escoltant (eavesdropping) a {INTERFACE} amb filtre: {FILTER}\n")

def process_packet(packet):
    if IP in packet and UDP in packet and Raw in packet:
        payload = packet[Raw].load

        print("=" * 60)
        print(f"📥 Rebut de {packet[IP].src}:{packet[UDP].sport}")
        print(f"📦 Contingut capturat: \n {packet[Raw].load.decode(errors="ignore")}\n")
        print("=" * 60)

# ▶️ Inicia l’esnifador (només lectura, sense reenviament)
sniff(filter=FILTER, iface=INTERFACE, prn=process_packet)
