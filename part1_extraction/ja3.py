# ja3.py
# Rôle : calculer les empreintes JA3 et JA3S
# JA3  = fingerprint du ClientHello (identifie le CLIENT)
# JA3S = fingerprint du ServerHello (identifie le SERVEUR)
# Ces empreintes sont des hash MD5 utilisés en threat intelligence

import hashlib

# Valeurs GREASE à exclure du calcul
VALEURS_GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a,
    0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
    0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}


def calculer_ja3(client_hello):
    """
    Calcule l'empreinte JA3 depuis un ClientHello parsé.
    
    Formule JA3 :
    MD5( version , cipher_suites , extensions , groupes_elliptiques , formats_point )
    
    client_hello : dictionnaire retourné par parser_client_hello()
    Retourne : (chaine_ja3_brute, hash_md5)
    """
    if not client_hello:
        return None, None
    
    # ① Version TLS
    version = str(client_hello.get("tls_version", 0))
    
    # ② Cipher suites (sans GREASE)
    ciphers = client_hello.get("cipher_suites", [])
    ciphers_str = "-".join(str(c) for c in ciphers if c not in VALEURS_GREASE)
    
    # ③ Types d'extensions (sans GREASE)
    extensions = client_hello.get("extensions", [])
    ext_types = [e["type"] for e in extensions if e["type"] not in VALEURS_GREASE]
    ext_str = "-".join(str(e) for e in ext_types)
    
    # ④ Groupes elliptiques
    groupes = client_hello.get("groupes_elliptiques", [])
    groupes_str = "-".join(str(g) for g in groupes if g not in VALEURS_GREASE)
    
    # ⑤ Formats de point EC
    formats = client_hello.get("formats_point_ec", [])
    formats_str = "-".join(str(f) for f in formats)
    
    # Assembler la chaîne JA3
    chaine_ja3 = f"{version},{ciphers_str},{ext_str},{groupes_str},{formats_str}"
    
    # Calculer le MD5
    hash_ja3 = hashlib.md5(chaine_ja3.encode()).hexdigest()
    
    return chaine_ja3, hash_ja3


def calculer_ja3s(server_hello):
    """
    Calcule l'empreinte JA3S depuis un ServerHello parsé.
    
    Formule JA3S :
    MD5( version , cipher_suite_choisie , extensions )
    
    server_hello : dictionnaire retourné par parser_server_hello()
    Retourne : (chaine_ja3s_brute, hash_md5)
    """
    if not server_hello:
        return None, None
    
    # ① Version TLS
    version = str(server_hello.get("tls_version", 0))
    
    # ② Cipher suite choisie par le serveur
    cipher = str(server_hello.get("cipher_suite_choisie", 0))
    
    # ③ Types d'extensions
    extensions = server_hello.get("extensions", [])
    ext_str = "-".join(str(e["type"]) for e in extensions
                       if e["type"] not in VALEURS_GREASE)
    
    # Assembler la chaîne JA3S
    chaine_ja3s = f"{version},{cipher},{ext_str}"
    
    # Calculer le MD5
    hash_ja3s = hashlib.md5(chaine_ja3s.encode()).hexdigest()
    
    return chaine_ja3s, hash_ja3s


def afficher_ja3(chaine, hash_md5, nom="JA3"):
    """Affiche les résultats JA3 de manière lisible."""
    print(f"\n  {nom} brut  : {chaine}")
    print(f"  {nom} MD5  : {hash_md5}")


# ─── TEST ───────────────────────────────────────────────
if __name__ == "__main__":
    # Test avec des données fictives
    client_hello_fictif = {
        "tls_version": 771,          # TLS 1.2
        "cipher_suites": [49195, 49199, 49196, 49200],
        "extensions": [{"type": 0}, {"type": 23}, {"type": 10}],
        "groupes_elliptiques": [29, 23, 24],
        "formats_point_ec": [0],
    }
    
    chaine, hash_md5 = calculer_ja3(client_hello_fictif)
    print("[*] Test JA3 avec données fictives :")
    afficher_ja3(chaine, hash_md5, "JA3")