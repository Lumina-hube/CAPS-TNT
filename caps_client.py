"""
caps_client.py - Client leger du poste agent (CAPS)

Role :
  - affiche l'ecran de connexion (la page Flask) en plein ecran, au premier plan,
    sans possibilite de le fermer ;
  - apres une connexion reussie, cache l'ecran et affiche un petit widget
    (nom, temps restant, bouton "Se deconnecter") ;
  - quand plus rien ne bouge (souris / clavier) pendant N secondes, ou quand
    la session expire, ou quand l'agent clique sur "Se deconnecter" :
    previent le serveur (/logout) et reaffiche l'ecran de connexion.

Variables d'environnement (toutes optionnelles) :
  CAPS_SERVEUR      adresse du serveur   (defaut : http://192.168.220.1:5000)
  CAPS_INACTIVITE   secondes d'inactivite avant verrouillage (defaut : 30)
  CAPS_TEST         "1" = mode test : fenetre normale, fermeture autorisee
"""

import ctypes
import datetime
import json
import os
import threading
import time
import urllib.request

import webview

SERVEUR = os.environ.get("CAPS_SERVEUR", "http://192.168.220.1:5000").rstrip("/")
INACTIVITE_SECONDES = int(os.environ.get("CAPS_INACTIVITE", "30"))
MODE_TEST = os.environ.get("CAPS_TEST") == "1"

etat = {"token": None, "exp": None, "nom": ""}
verrou = threading.Lock()


# --- Detection d'inactivite (Windows) -----------------------------------------
class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]


def secondes_inactivite():
    """Secondes ecoulees depuis le dernier mouvement de souris ou touche clavier.
    Le compteur Windows (GetTickCount) repart a zero tous les ~49 jours : comme
    le poste ne s'eteint jamais, on calcule la difference modulo 2**32."""
    info = LASTINPUTINFO()
    info.cbSize = ctypes.sizeof(LASTINPUTINFO)
    ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info))
    maintenant = ctypes.windll.kernel32.GetTickCount() & 0xFFFFFFFF
    return ((maintenant - info.dwTime) & 0xFFFFFFFF) / 1000.0


# --- Communication avec le serveur --------------------------------------------
def envoyer_deconnexion(token):
    """Enregistre la deconnexion dans le journal du serveur (route /logout)."""
    requete = urllib.request.Request(
        SERVEUR + "/logout",
        data=json.dumps({"token": token}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(requete, timeout=5):
            pass
    except Exception as erreur:
        # Token expire (401) ou serveur injoignable : on verrouille quand meme.
        print(f"[CAPS] Deconnexion non enregistree : {erreur}")


# --- Verrouillage --------------------------------------------------------------
def verrouiller(raison):
    with verrou:
        token = etat["token"]
        if token is None:
            return
        etat["token"] = None
        etat["exp"] = None
    print(f"[CAPS] Verrouillage : {raison}")
    envoyer_deconnexion(token)
    widget.hide()
    # On ajoute ?verrouille=1 : la page elle-meme videra son localStorage des
    # son chargement (voir index.html), au lieu de compter sur evaluate_js
    # juste avant la navigation, dont le timing n'est pas garanti.
    fenetre_connexion.load_url(SERVEUR + "/?verrouille=1")
    fenetre_connexion.show()


# --- Fonctions appelees depuis les pages (JavaScript -> Python) ---------------
# Une seule classe, utilisee par les DEUX fenetres : certaines versions de
# pywebview ne separent pas correctement l'API par fenetre quand on passe deux
# objets differents (la derniere ecrase la premiere cote JavaScript). Avec une
# API commune, chaque fenetre voit toutes les methodes, ce qui evite le probleme.
class ApiCaps:
    """Appelee depuis index.html (connexion_ok) et depuis le widget (deconnecter)."""

    def connexion_ok(self, token, exp, role, nom):
        with verrou:
            etat["token"] = token
            etat["exp"] = datetime.datetime.fromisoformat(exp)
            etat["nom"] = nom
        fenetre_connexion.hide()
        widget.show()
        try:
            # Affichage immediat : sans ca, le widget reste vide ("-") jusqu'au
            # prochain passage de la boucle de surveillance (jusqu'a 1 seconde).
            widget.evaluate_js(f"maj({json.dumps(nom)}, {json.dumps(texte_restant(etat['exp'] - datetime.datetime.now(datetime.timezone.utc)))})")
            widget.evaluate_js(f"configurerRole({json.dumps(role)})")
        except Exception as erreur:
            print(f"[CAPS] Mise a jour immediate du widget impossible : {erreur}")
        return True

    def deconnecter(self):
        threading.Thread(target=verrouiller, args=("deconnexion volontaire",), daemon=True).start()

    def ouvrir_application(self):
        """Rouvre la grande fenetre (deja chargee sur le panneau RSSI/superviseur
        depuis la connexion), sans toucher a la session ni au widget."""
        fenetre_connexion.show()


api = ApiCaps()


# --- Petit widget affiche pendant le service ----------------------------------
HTML_WIDGET = """
<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8">
<style>
  body { margin:0; padding:14px; background:#004b29; color:#fff;
         font-family:'Segoe UI',sans-serif; font-size:13px; }
  #n { font-weight:700; font-size:15px; }
  #t { margin:8px 0 12px; color:#b4e8d8; }
  button { width:100%; padding:9px; border:0; border-radius:4px;
           font-weight:700; cursor:pointer; margin-top:6px; }
  #btn-deconnecter { background:#f4cf00; color:#1d272c; }
  #btn-outils { background:#ffffff22; color:#fff; display:none; }
</style></head>
<body>
  <div id="n">-</div>
  <div id="t">-</div>
  <button id="btn-outils" onclick="pywebview.api.ouvrir_application()">Tableau de bord</button>
  <button id="btn-deconnecter" onclick="pywebview.api.deconnecter()">Se deconnecter</button>
  <script>
    function maj(nom, texte) {
      document.getElementById('n').textContent = nom;
      document.getElementById('t').textContent = texte;
    }
    function configurerRole(role) {
      // Seuls le RSSI (admin) et le superviseur ont des outils supplementaires
      // a ouvrir depuis le widget (creation de comptes, journal, validation
      // des demandes de prolongation).
      const bouton = document.getElementById('btn-outils');
      bouton.style.display = (role === 'admin' || role === 'superviseur') ? 'block' : 'none';
    }
  </script>
</body></html>
"""


def texte_restant(restant):
    if restant > datetime.timedelta(days=2):
        return "Session sans limite"
    total_minutes = int(restant.total_seconds() // 60)
    return f"Temps restant : {total_minutes // 60} h {total_minutes % 60:02d} min"


# --- Surveillance (tourne en arriere-plan) -------------------------------------
def surveillance():
    while True:
        time.sleep(1)
        with verrou:
            token, exp, nom = etat["token"], etat["exp"], etat["nom"]
        if token is None:
            continue

        restant = exp - datetime.datetime.now(datetime.timezone.utc)
        if restant.total_seconds() <= 0:
            verrouiller("session expiree")
            continue
        if secondes_inactivite() >= INACTIVITE_SECONDES:
            verrouiller("inactivite")
            continue

        try:
            widget.evaluate_js(f"maj({json.dumps(nom)}, {json.dumps(texte_restant(restant))})")
        except Exception:
            pass


def refuser_fermeture(*args):
    return False  # annule la fermeture de la fenetre


# --- Creation des fenetres -----------------------------------------------------
largeur_ecran = ctypes.windll.user32.GetSystemMetrics(0)

fenetre_connexion = webview.create_window(
    "CAPS",
    SERVEUR,
    js_api=api,
    fullscreen=not MODE_TEST,
    on_top=True,
    width=1100,
    height=750,
)

widget = webview.create_window(
    "CAPS - Session",
    html=HTML_WIDGET,
    js_api=api,
    width=260,
    height=140,
    x=largeur_ecran - 280,
    y=20,
    frameless=True,
    on_top=True,
    hidden=True,
    resizable=False,
)

if not MODE_TEST:
    fenetre_connexion.events.closing += refuser_fermeture
    widget.events.closing += refuser_fermeture

if __name__ == "__main__":
    webview.start(surveillance, debug=MODE_TEST)