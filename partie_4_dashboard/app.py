from flask import Flask, render_template, jsonify
import random  # On l'utilise pour générer de fausses données en attendant le Membre C

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

def generer_fausses_alertes():
    return [
        {"id": 1, "severite": "critical", "message": "Utilisation de TLS 1.0 (obsolète)", "ip_source": "192.168.1.50"},
        {"id": 2, "severite": "warning", "message": "Cipher suite faible détectée", "ip_source": "192.168.1.22"},
        {"id": 3, "severite": "info", "message": "Connexion TLS 1.3 réussie", "ip_source": "192.168.1.10"}
    ]

# 1. Route pour afficher la page web
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

# 2. Route API qui donne les données en JSON
@app.route('/api/alertes')
def api_alertes():
    alertes = generer_fausses_alertes()
    return jsonify(alertes)  # Transforme la liste en format JSON pour le web

if __name__ == '__main__':
    app.run(debug=True)