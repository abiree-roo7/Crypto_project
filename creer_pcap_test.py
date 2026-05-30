# creer_pcap_test.py
# Crée un fichier PCAP de test avec de vrais paquets TLS simulés

from scapy.all import *
from scapy.layers.tls.all import *

# Paquet ClientHello TLS simulé (octets réels d'un vrai ClientHello)
client_hello_bytes = bytes([
    0x16, 0x03, 0x01, 0x00, 0x68,  # TLS Record : Handshake, TLS 1.0, longueur
    0x01, 0x00, 0x00, 0x64,         # ClientHello, longueur
    0x03, 0x03,                     # Version : TLS 1.2
    # Random (32 octets)
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    0x00,                           # Session ID length = 0
    0x00, 0x04,                     # Cipher suites length = 4
    0xc0, 0x2b,                     # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc0, 0x2c,                     # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0x01,                           # Compression methods length = 1
    0x00,                           # No compression
    0x00, 0x1d,                     # Extensions length = 29
    # Extension SNI (type 0)
    0x00, 0x00,                     # Type : SNI
    0x00, 0x11,                     # Longueur
    0x00, 0x0f,                     # Server name list length
    0x00,                           # Type : host_name
    0x00, 0x0c,                     # Name length = 12
    # "example.com" en ASCII
    0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,0x2e,0x63,0x6f,0x6d,0x00,
    # Extension Supported Groups (type 10)
    0x00, 0x0a,
    0x00, 0x04,
    0x00, 0x02,
    0x00, 0x1d,  # x25519
    0x00, 0x17,  # secp256r1
])

# Construire le paquet réseau
paquet = (
    IP(src="192.168.1.10", dst="93.184.216.34") /
    TCP(sport=54231, dport=443, flags="PA") /
    Raw(load=client_hello_bytes)
)

# Sauvegarder dans un fichier PCAP
wrpcap("test.pcap", [paquet])
print("[+] Fichier test.pcap créé avec succès !")
print("[+] Tu peux maintenant lancer : python -m part1_extraction.session test.pcap")