# capture.py
# Rôle : capturer les paquets réseau (live ou fichier PCAP)
# et filtrer uniquement les paquets TLS (port 443)

import scapy.all as scapy
import pyshark
import os

def capture_live(interface="eth0", packet_count=100):
    """
    Capture les paquets en direct sur une interface réseau.
    interface : nom de l'interface (ex: 'eth0', 'Wi-Fi', 'Ethernet')
    packet_count : nombre de paquets à capturer
    """
    print(f"[*] Capture live sur l'interface : {interface}")
    
    paquets = scapy.sniff(
        iface=interface,
        filter="tcp port 443",   # uniquement le trafic TLS
        count=packet_count,
        store=True
    )
    
    print(f"[+] {len(paquets)} paquets capturés")
    return paquets


def capture_depuis_pcap(chemin_fichier):
    """
    Lit un fichier PCAP déjà enregistré.
    chemin_fichier : chemin vers le fichier .pcap
    """
    if not os.path.exists(chemin_fichier):
        print(f"[!] Fichier introuvable : {chemin_fichier}")
        return []
    
    print(f"[*] Lecture du fichier PCAP : {chemin_fichier}")
    paquets = scapy.rdpcap(chemin_fichier)
    
    # Filtrer uniquement port 443
    paquets_tls = [p for p in paquets 
                   if p.haslayer(scapy.TCP) and 
                   (p[scapy.TCP].dport == 443 or p[scapy.TCP].sport == 443)]
    
    print(f"[+] {len(paquets_tls)} paquets TLS trouvés dans le fichier")
    return paquets_tls


def extraire_payload(paquet):
    """
    Extrait les octets bruts d'un paquet TCP.
    Retourne None si le paquet n'a pas de données.
    """
    if paquet.haslayer(scapy.Raw):
        return bytes(paquet[scapy.Raw].load)
    return None


def est_tls(data):
    """
    Vérifie si les données sont un message TLS.
    Le premier octet d'un paquet TLS vaut toujours entre 20 et 23.
    20 = ChangeCipherSpec
    21 = Alert
    22 = Handshake  ← c'est celui qui nous intéresse
    23 = ApplicationData
    """
    if data and len(data) > 5:
        premier_octet = data[0]
        return 20 <= premier_octet <= 23
    return False


def est_client_hello(data):
    """
    Vérifie si c'est un message ClientHello.
    TLS Handshake (22) + type ClientHello (1)
    """
    if est_tls(data) and data[0] == 22 and len(data) > 6:
        return data[5] == 1
    return False


def est_server_hello(data):
    """
    Vérifie si c'est un message ServerHello.
    TLS Handshake (22) + type ServerHello (2)
    """
    if est_tls(data) and data[0] == 22 and len(data) > 6:
        return data[5] == 2
    return False


# ─── TEST ───────────────────────────────────────────────
if __name__ == "__main__":
    # Pour tester avec un fichier PCAP (plus simple pour débuter)
    # Télécharge un fichier PCAP de test sur :
    # https://wiki.wireshark.org/SampleCaptures
    
    chemin = "test.pcap"   # remplace par ton fichier PCAP
    
    if os.path.exists(chemin):
        paquets = capture_depuis_pcap(chemin)
        for p in paquets[:5]:   # afficher les 5 premiers
            data = extraire_payload(p)
            if data:
                print(f"TLS: {est_tls(data)} | "
                      f"ClientHello: {est_client_hello(data)} | "
                      f"ServerHello: {est_server_hello(data)}")
    else:
        print("[!] Mets un fichier test.pcap dans le dossier pour tester")