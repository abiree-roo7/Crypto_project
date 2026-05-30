# tls_parser.py
# Rôle : parser les messages ClientHello et ServerHello
# et extraire toutes les métadonnées TLS importantes

import struct

# Dictionnaire des versions TLS connues
VERSIONS_TLS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# Valeurs GREASE à ignorer (RFC 8701)
# Ce sont des valeurs réservées que les navigateurs envoient
# pour tester la compatibilité — on les ignore dans JA3
VALEURS_GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a,
    0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
    0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}


def parser_client_hello(data):
    """
    Parse un message ClientHello TLS.
    Retourne un dictionnaire avec toutes les infos extraites.
    data : octets bruts du paquet TLS
    """
    resultat = {
        "type": "ClientHello",
        "tls_version": None,
        "version_nom": None,
        "random": None,
        "session_id": None,
        "cipher_suites": [],
        "methodes_compression": [],
        "extensions": [],
        "sni": None,              # nom du serveur demandé
        "groupes_elliptiques": [],
        "formats_point_ec": [],
    }
    
    try:
        # Vérifier que c'est bien un TLS Handshake ClientHello
        if len(data) < 43:
            return None
        if data[0] != 22:    # 22 = Handshake
            return None
        if data[5] != 1:     # 1 = ClientHello
            return None
        
        pos = 9  # position de départ après les en-têtes TLS
        
        # ── Version TLS proposée par le client ──
        version = struct.unpack("!H", data[pos:pos+2])[0]
        resultat["tls_version"] = version
        resultat["version_nom"] = VERSIONS_TLS.get(version, f"Inconnu (0x{version:04x})")
        pos += 2
        
        # ── Random (32 octets) ──
        resultat["random"] = data[pos:pos+32].hex()
        pos += 32
        
        # ── Session ID ──
        session_id_len = data[pos]
        pos += 1
        resultat["session_id"] = data[pos:pos+session_id_len].hex()
        pos += session_id_len
        
        # ── Cipher Suites ──
        cipher_suites_len = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 2
        for i in range(0, cipher_suites_len, 2):
            suite = struct.unpack("!H", data[pos+i:pos+i+2])[0]
            if suite not in VALEURS_GREASE:
                resultat["cipher_suites"].append(suite)
        pos += cipher_suites_len
        
        # ── Méthodes de compression ──
        compression_len = data[pos]
        pos += 1
        resultat["methodes_compression"] = list(data[pos:pos+compression_len])
        pos += compression_len
        
        # ── Extensions ──
        if pos + 2 <= len(data):
            extensions_len = struct.unpack("!H", data[pos:pos+2])[0]
            pos += 2
            fin_extensions = pos + extensions_len
            
            while pos + 4 <= fin_extensions:
                ext_type = struct.unpack("!H", data[pos:pos+2])[0]
                ext_len  = struct.unpack("!H", data[pos+2:pos+4])[0]
                ext_data = data[pos+4:pos+4+ext_len]
                pos += 4 + ext_len
                
                if ext_type in VALEURS_GREASE:
                    continue
                
                ext_info = {"type": ext_type, "longueur": ext_len}
                
                # Extension SNI (type 0) — nom du serveur
                if ext_type == 0 and len(ext_data) > 5:
                    sni_len = struct.unpack("!H", ext_data[3:5])[0]
                    resultat["sni"] = ext_data[5:5+sni_len].decode("utf-8", errors="ignore")
                    ext_info["sni"] = resultat["sni"]
                
                # Extension Supported Groups (type 10)
                elif ext_type == 10 and len(ext_data) >= 2:
                    groupes_len = struct.unpack("!H", ext_data[0:2])[0]
                    for i in range(0, groupes_len, 2):
                        if i+2 <= len(ext_data)-2:
                            g = struct.unpack("!H", ext_data[2+i:2+i+2])[0]
                            if g not in VALEURS_GREASE:
                                resultat["groupes_elliptiques"].append(g)
                
                # Extension EC Point Formats (type 11)
                elif ext_type == 11 and len(ext_data) >= 1:
                    formats_len = ext_data[0]
                    resultat["formats_point_ec"] = list(ext_data[1:1+formats_len])
                
                resultat["extensions"].append(ext_info)
        
        return resultat
    
    except Exception as e:
        print(f"[!] Erreur parsing ClientHello : {e}")
        return None


def parser_server_hello(data):
    """
    Parse un message ServerHello TLS.
    Retourne un dictionnaire avec les infos du serveur.
    """
    resultat = {
        "type": "ServerHello",
        "tls_version": None,
        "version_nom": None,
        "random": None,
        "cipher_suite_choisie": None,
        "compression": None,
        "extensions": [],
    }
    
    try:
        if len(data) < 43:
            return None
        if data[0] != 22:   # Handshake
            return None
        if data[5] != 2:    # ServerHello
            return None
        
        pos = 9
        
        # Version
        version = struct.unpack("!H", data[pos:pos+2])[0]
        resultat["tls_version"] = version
        resultat["version_nom"] = VERSIONS_TLS.get(version, f"Inconnu (0x{version:04x})")
        pos += 2
        
        # Random
        resultat["random"] = data[pos:pos+32].hex()
        pos += 32
        
        # Session ID
        session_id_len = data[pos]
        pos += 1 + session_id_len
        
        # Cipher suite choisie par le serveur
        suite = struct.unpack("!H", data[pos:pos+2])[0]
        resultat["cipher_suite_choisie"] = suite
        pos += 2
        
        # Compression
        resultat["compression"] = data[pos]
        pos += 1
        
        # Extensions
        if pos + 2 <= len(data):
            extensions_len = struct.unpack("!H", data[pos:pos+2])[0]
            pos += 2
            fin = pos + extensions_len
            while pos + 4 <= fin:
                ext_type = struct.unpack("!H", data[pos:pos+2])[0]
                ext_len  = struct.unpack("!H", data[pos+2:pos+4])[0]
                pos += 4 + ext_len
                if ext_type not in VALEURS_GREASE:
                    resultat["extensions"].append({"type": ext_type})
        
        return resultat
    
    except Exception as e:
        print(f"[!] Erreur parsing ServerHello : {e}")
        return None


# ─── TEST ───────────────────────────────────────────────
if __name__ == "__main__":
    print("[*] Test du parser TLS")
    print("[*] Ce fichier s'utilise importé depuis session.py")
    print("[*] Exemple d'utilisation :")
    print("    from part1_extraction.tls_parser import parser_client_hello")