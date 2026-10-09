"""
app.py - Serveur Flask du projet IAM
"""

import os
import re
import html
import time
import secrets
import sqlite3
import datetime
import smtplib
from collections import defaultdict
from email.mime.text import MIMEText

from flask import Flask, request, jsonify, render_template
from werkzeug.security import check_password_hash, generate_password_hash
import jwt

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # 64 Ko : largement suffisant pour nos requetes JSON, limite les abus

# --- Cle secrete JWT ---------------------------------------------------------
# On refuse d'utiliser une valeur par defaut devinable. Si IAM_CLE_SECRETE n'est
# pas definie, on genere une cle aleatoire pour cette execution : moins pratique
# (les sessions ne survivent pas a un redemarrage) mais jamais dangereux.
CLE_SECRETE = os.environ.get("IAM_CLE_SECRETE")
if not CLE_SECRETE:
    CLE_SECRETE = secrets.token_hex(32)
    print("[ATTENTION] IAM_CLE_SECRETE n'est pas definie : une cle temporaire aleatoire a ete generee.")
    print("[ATTENTION] Toutes les sessions seront invalidees au prochain redemarrage du serveur.")
    print("[ATTENTION] Definissez IAM_CLE_SECRETE pour un fonctionnement stable et securise.")

EMAIL_EXPEDITEUR = os.environ.get("IAM_EMAIL_EXPEDITEUR")
EMAIL_MOT_DE_PASSE = os.environ.get("IAM_EMAIL_MOT_DE_PASSE")
SMTP_SERVEUR = "smtp.gmail.com"
SMTP_PORT = 587

IAM_BASE_URL = os.environ.get("IAM_BASE_URL", "http://127.0.0.1:5000").rstrip("/")

FUSEAU_BENIN = datetime.timezone(datetime.timedelta(hours=1))
HEURE_EXPIRATION_FIXE = 9
DELAI_MIN_ENTRE_SERVICES_HEURES = 71
DUREE_PROLONGATION_HEURES = 1
FENETRE_DEMANDE_PROLONGATION_MINUTES = 30
DUREE_VALIDITE_LIEN_EMAIL_HEURES = 1

JOURS_FR = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"]

RAISONS_VALIDES = ("incident", "maintenance", "retard_taches", "autre")
ROLES_VALIDES = ("agent", "chef", "superviseur", "admin")

PERMISSIONS_PAR_ROLE = {
    "agent": {"demander_prolongation", "statut_demande"},
    "chef": set(),
    "superviseur": {"valider_prolongation", "statut_demande"},
    "admin": {"creer_utilisateur", "modifier_utilisateur", "activer_utilisateur", "desactiver_utilisateur", "journal"},
}

# --- Protection contre la force brute sur /login -----------------------------
# Stockage en memoire (suffisant pour un seul processus de demo/soutenance).
LIMITE_TENTATIVES = 5
FENETRE_LIMITE_SECONDES = 300  # 5 minutes
_tentatives_echouees = defaultdict(list)

# Hash factice utilise pour egaliser le temps de reponse quand l'utilisateur n'existe pas,
# afin qu'on ne puisse pas deviner l'existence d'un compte en mesurant le temps de reponse.
_HASH_FACTICE = generate_password_hash(secrets.token_hex(16))


def cle_limite(nom, ip):
    return f"{nom.lower()}|{ip}"


def trop_de_tentatives(cle):
    maintenant = time.time()
    horodatages = [t for t in _tentatives_echouees[cle] if maintenant - t < FENETRE_LIMITE_SECONDES]
    _tentatives_echouees[cle] = horodatages
    return len(horodatages) >= LIMITE_TENTATIVES


def enregistrer_echec(cle):
    _tentatives_echouees[cle].append(time.time())


def reinitialiser_tentatives(cle):
    _tentatives_echouees.pop(cle, None)


@app.after_request
def ajouter_en_tetes_securite(reponse):
    reponse.headers["X-Content-Type-Options"] = "nosniff"
    reponse.headers["X-Frame-Options"] = "DENY"
    reponse.headers["Referrer-Policy"] = "no-referrer"
    return reponse


def envoyer_email(destinataire, sujet, corps, html_mode=False):
    if not destinataire:
        return False
    if not EMAIL_EXPEDITEUR or not EMAIL_MOT_DE_PASSE:
        print("[ATTENTION] Identifiants email non configures (variables d'environnement manquantes).")
        return False
    try:
        message = MIMEText(corps, "html" if html_mode else "plain")
        message["Subject"] = sujet
        message["From"] = EMAIL_EXPEDITEUR
        message["To"] = destinataire

        with smtplib.SMTP(SMTP_SERVEUR, SMTP_PORT) as serveur:
            serveur.starttls()
            serveur.login(EMAIL_EXPEDITEUR, EMAIL_MOT_DE_PASSE)
            serveur.send_message(message)
        return True
    except Exception as erreur:
        print(f"[ATTENTION] Echec de l'envoi d'email a {destinataire} : {erreur}")
        return False


def get_connexion_bdd():
    connexion = sqlite3.connect("database.db", timeout=10)
    connexion.row_factory = sqlite3.Row
    connexion.execute("PRAGMA busy_timeout = 10000")
    connexion.execute("PRAGMA foreign_keys = ON")
    return connexion


def formater_date_fr(date_obj):
    nom_jour = JOURS_FR[date_obj.weekday()]
    return f"{nom_jour} a {date_obj.strftime('%Hh%M')}"


def decoder_token(token):
    if not token:
        return None, "Jeton manquant."
    try:
        payload = jwt.decode(token, CLE_SECRETE, algorithms=["HS256"])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, "Session expiree, veuillez vous reconnecter."
    except jwt.InvalidTokenError:
        return None, "Jeton invalide."


def id_valide(valeur):
    return isinstance(valeur, int) and not isinstance(valeur, bool) and valeur > 0


def authentifier_requete(donnees, permission=None):
    payload, erreur = decoder_token((donnees or {}).get("token"))
    if erreur:
        return None, erreur, 401

    utilisateur_id = payload.get("utilisateur_id")
    if not id_valide(utilisateur_id):
        return None, "Jeton invalide.", 401

    connexion = get_connexion_bdd()
    utilisateur = connexion.execute(
        "SELECT id, nom, role, poste, peut_valider_prolongation, actif "
        "FROM utilisateurs WHERE id = ?", (utilisateur_id,)
    ).fetchone()
    connexion.close()

    if utilisateur is None or utilisateur["actif"] == 0:
        return None, "Compte inexistant ou desactive.", 403

    role = utilisateur["role"]
    if role not in ROLES_VALIDES:
        return None, "Role non autorise.", 403

    if permission and permission not in PERMISSIONS_PAR_ROLE.get(role, set()):
        return None, "Vous n'etes pas autorise a effectuer cette action.", 403

    payload["nom"] = utilisateur["nom"]
    payload["role"] = role
    payload["poste"] = utilisateur["poste"]
    payload["peut_valider_prolongation"] = bool(utilisateur["peut_valider_prolongation"])
    return payload, None, 200


def prochaine_expiration_09h(heure_debut):
    demain = heure_debut + datetime.timedelta(days=1)
    return demain.replace(hour=HEURE_EXPIRATION_FIXE, minute=0, second=0, microsecond=0)


def dans_fenetre_prolongation(heure_actuelle, heure_expiration):
    debut = heure_expiration - datetime.timedelta(minutes=FENETRE_DEMANDE_PROLONGATION_MINUTES)
    return debut <= heure_actuelle < heure_expiration


def journaliser(connexion, utilisateur_id, nom_utilisateur, action, details=""):
    connexion.execute(
        "INSERT INTO journal_activite (utilisateur_id, nom_utilisateur, action, details, heure) "
        "VALUES (?, ?, ?, ?, ?)",
        (utilisateur_id, nom_utilisateur, action, details, datetime.datetime.now(FUSEAU_BENIN).isoformat())
    )


def page_html(message, ok=True):
    couleur = "#48c9a1" if ok else "#ff8a85"
    return f"""
    <!DOCTYPE html>
    <html lang="fr"><head><meta charset="UTF-8">
    <title>SBIR - Notification</title>
    <style>
      body {{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
              background:#0d1b2a; font-family:'Segoe UI',system-ui,sans-serif; }}
      .boite {{ background:#142c3f; border:1px solid #274b5e; border-radius:8px; padding:32px 40px;
                max-width:420px; text-align:center; color:#e6edf3; }}
      .boite p {{ color:{couleur}; font-size:1rem; }}
    </style></head>
    <body><div class="boite"><p>{message}</p></div></body></html>
    """


def page_confirmation(demande_id, decision_libelle, token_action):
    return f"""
    <!DOCTYPE html>
    <html lang="fr"><head><meta charset="UTF-8">
    <title>SBIR - Confirmation</title>
    <style>
      body {{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
              background:#0d1b2a; font-family:'Segoe UI',system-ui,sans-serif; }}
      .boite {{ background:#142c3f; border:1px solid #274b5e; border-radius:8px; padding:32px 40px;
                max-width:420px; text-align:center; color:#e6edf3; }}
      button {{ margin-top:18px; padding:12px 22px; background:#3ba98c; color:#04140f; border:none;
                border-radius:4px; font-weight:600; cursor:pointer; font-size:0.9rem; }}
      button:hover {{ background:#48c9a1; }}
    </style></head>
    <body><div class="boite">
      <p>Confirmez-vous : <b>{decision_libelle}</b> la demande #{demande_id} ?</p>
      <form method="POST" action="/decision_email/confirmer">
        <input type="hidden" name="token" value="{token_action}">
        <button type="submit">Confirmer</button>
      </form>
    </div></body></html>
    """


def calculer_nouvelle_expiration(session_liee, heure_traitement):
    expiration_actuelle = datetime.datetime.fromisoformat(session_liee["heure_expiration"])
    base_calcul = max(expiration_actuelle, heure_traitement)
    return base_calcul + datetime.timedelta(hours=DUREE_PROLONGATION_HEURES)


def valider_token_decision(token_action):
    """Verifie le jeton et l'etat de la demande. Ne modifie rien en base.
    Retourne (payload, demande, superviseur, message_erreur)."""
    try:
        payload = jwt.decode(token_action, CLE_SECRETE, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None, None, None, "Ce lien a expire. Connectez-vous a l'application pour traiter la demande."
    except jwt.InvalidTokenError:
        return None, None, None, "Lien invalide."

    if payload.get("action") != "decision_email" or payload.get("decision") not in ("valider", "refuser"):
        return None, None, None, "Lien invalide."

    connexion = get_connexion_bdd()
    superviseur = connexion.execute(
        "SELECT * FROM utilisateurs WHERE id = ? AND actif = 1", (payload["utilisateur_id"],)
    ).fetchone()
    if superviseur is None or superviseur["role"] != "superviseur" or not superviseur["peut_valider_prolongation"]:
        connexion.close()
        return None, None, None, "Vous n'etes plus autorise a traiter cette demande."

    demande = connexion.execute(
        "SELECT * FROM demandes_prolongation WHERE id = ?", (payload["demande_id"],)
    ).fetchone()
    connexion.close()

    if demande is None:
        return None, None, None, "Demande introuvable."
    if demande["statut"] != "en_attente":
        return None, None, None, f"Cette demande a deja ete traitee (statut actuel : {demande['statut']})."

    return payload, demande, superviseur, None


@app.route("/")
def accueil():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    donnees = request.get_json(silent=True) or {}

    if not isinstance(donnees.get("nom"), str) or not isinstance(donnees.get("mot_de_passe"), str):
        return jsonify({"erreur": "Le nom et le mot de passe sont obligatoires"}), 400

    nom = donnees["nom"].strip()
    mot_de_passe = donnees["mot_de_passe"]
    if not nom or not mot_de_passe or len(nom) > 100:
        return jsonify({"erreur": "Identifiants invalides."}), 400

    ip_client = request.remote_addr or "inconnu"
    cle = cle_limite(nom, ip_client)

    if trop_de_tentatives(cle):
        return jsonify({"erreur": "Trop de tentatives echouees. Reessayez dans quelques minutes."}), 429

    connexion = get_connexion_bdd()
    utilisateur = connexion.execute(
        "SELECT * FROM utilisateurs WHERE nom = ?", (nom,)
    ).fetchone()

    if utilisateur is None:
        check_password_hash(_HASH_FACTICE, mot_de_passe)  # egalise le temps de reponse
        connexion.close()
        enregistrer_echec(cle)
        return jsonify({"erreur": "Identifiants incorrects."}), 401

    if not check_password_hash(utilisateur["mot_de_passe_hash"], mot_de_passe):
        connexion.close()
        enregistrer_echec(cle)
        return jsonify({"erreur": "Identifiants incorrects."}), 401

    reinitialiser_tentatives(cle)

    if utilisateur["actif"] == 0:
        connexion.close()
        return jsonify({"erreur": "Ce compte a ete desactive. Contactez le RSSI."}), 403

    heure_debut = datetime.datetime.now(FUSEAU_BENIN)

    # Une connexion applicative ne doit pas créer une nouvelle session de service
    # si l'agent possède déjà une session encore valide.
    # Il peut donc se déconnecter/reconnecter autant de fois qu'il le souhaite
    # pendant la durée de sa session.
    session_id = None
    session_existante = None

    if utilisateur["token_expire"] == 1:
        session_existante = connexion.execute(
            "SELECT id, heure_expiration, statut FROM sessions "
            "WHERE utilisateur_id = ? ORDER BY heure_expiration DESC LIMIT 1",
            (utilisateur["id"],)
        ).fetchone()

        if session_existante is not None:
            derniere_expiration = datetime.datetime.fromisoformat(
                session_existante["heure_expiration"]
            )

            # Session de service encore valide : on la réutilise.
            if heure_debut < derniere_expiration:
                session_id = session_existante["id"]
                heure_expiration = derniere_expiration

            # Session expirée : le délai réglementaire de 71 h s'applique.
            else:
                prochaine_connexion_possible = derniere_expiration + datetime.timedelta(
                    hours=DELAI_MIN_ENTRE_SERVICES_HEURES
                )
                if heure_debut < prochaine_connexion_possible:
                    connexion.close()
                    return jsonify({
                        "erreur": (
                            f"Votre prochaine connexion possible est le "
                            f"{formater_date_fr(prochaine_connexion_possible)}."
                        )
                    }), 403
                # Le délai réglementaire est écoulé : une nouvelle session peut commencer.
                heure_expiration = prochaine_expiration_09h(heure_debut)

    if utilisateur["token_expire"] == 0:
        heure_expiration = heure_debut + datetime.timedelta(days=36500)

    # Aucune session valide à réutiliser : création d'une nouvelle session de service.
    if session_id is None:
        curseur = connexion.execute(
            "INSERT INTO sessions (utilisateur_id, heure_debut, heure_expiration, statut) "
            "VALUES (?, ?, ?, ?)",
            (utilisateur["id"], heure_debut.isoformat(), heure_expiration.isoformat(), "actif")
        )
        session_id = curseur.lastrowid

    charge_utile = {
        "utilisateur_id": utilisateur["id"],
        "session_id": session_id,
        "nom": utilisateur["nom"],
        "role": utilisateur["role"],
        "poste": utilisateur["poste"],
        "peut_valider_prolongation": bool(utilisateur["peut_valider_prolongation"]),
        "iat": heure_debut,
        "exp": heure_expiration,
    }
    token = jwt.encode(charge_utile, CLE_SECRETE, algorithm="HS256")

    journaliser(connexion, utilisateur["id"], utilisateur["nom"], "connexion", f"role={utilisateur['role']}")
    connexion.commit()
    connexion.close()

    peut_demander = (
        utilisateur["role"] == "agent"
        and dans_fenetre_prolongation(heure_debut, heure_expiration)
    )

    return jsonify({
        "token": token,
        "role": utilisateur["role"],
        "poste": utilisateur["poste"],
        "exp": heure_expiration.isoformat(),
        "peut_demander_prolongation": peut_demander,
        "fenetre_prolongation_minutes": FENETRE_DEMANDE_PROLONGATION_MINUTES,
    })


@app.route("/demander_prolongation", methods=["POST"])
def demander_prolongation():
    donnees = request.get_json(silent=True) or {}
    payload, erreur, code = authentifier_requete(donnees, "demander_prolongation")
    if erreur:
        return jsonify({"erreur": erreur}), code

    raison = donnees.get("raison")
    if raison not in RAISONS_VALIDES:
        return jsonify({"erreur": "Raison invalide."}), 400

    texte_autre = donnees.get("texte_autre", "")
    if raison == "autre":
        if not isinstance(texte_autre, str) or not texte_autre.strip():
            return jsonify({"erreur": "Veuillez preciser la raison."}), 400
        texte_autre = texte_autre.strip()[:200]
    else:
        texte_autre = None

    connexion = get_connexion_bdd()
    session_active = connexion.execute(
        """
        SELECT id, utilisateur_id, heure_debut, heure_expiration, statut
        FROM sessions
        WHERE id = ? AND utilisateur_id = ?
        """,
        (payload.get("session_id"), payload["utilisateur_id"])
    ).fetchone()

    if session_active is None:
        connexion.close()
        return jsonify({"erreur": "Session introuvable ou non associee a ce compte."}), 404

    heure_demande = datetime.datetime.now(FUSEAU_BENIN)
    try:
        heure_expiration = datetime.datetime.fromisoformat(session_active["heure_expiration"])
    except (ValueError, TypeError):
        connexion.close()
        return jsonify({"erreur": "Date d'expiration de session invalide."}), 500

    if not dans_fenetre_prolongation(heure_demande, heure_expiration):
        connexion.close()
        if heure_demande < heure_expiration - datetime.timedelta(minutes=FENETRE_DEMANDE_PROLONGATION_MINUTES):
            return jsonify({
                "erreur": "La demande est disponible uniquement pendant les 30 dernieres minutes de la session."
            }), 403
        return jsonify({
            "erreur": "La session est expiree. La demande de prolongation n'est plus possible."
        }), 403

    deja = connexion.execute(
        "SELECT id FROM demandes_prolongation WHERE session_id = ? AND statut = 'en_attente' LIMIT 1",
        (session_active["id"],)
    ).fetchone()
    if deja is not None:
        connexion.close()
        return jsonify({"erreur": "Une demande de prolongation est deja en attente."}), 409

    curseur = connexion.execute(
        "INSERT INTO demandes_prolongation (session_id, heure_demande, raison, texte_autre, statut) "
        "VALUES (?, ?, ?, ?, ?)",
        (session_active["id"], heure_demande.isoformat(), raison, texte_autre, "en_attente")
    )
    demande_id = curseur.lastrowid

    journaliser(
        connexion, payload["utilisateur_id"], payload["nom"],
        "demande_prolongation", f"demande_id={demande_id}, raison={raison}"
    )

    superviseurs = connexion.execute(
        "SELECT id, email FROM utilisateurs "
        "WHERE peut_valider_prolongation = 1 AND role = 'superviseur' AND actif = 1"
    ).fetchall()
    connexion.commit()
    connexion.close()

    expiration_lien = heure_demande + datetime.timedelta(hours=DUREE_VALIDITE_LIEN_EMAIL_HEURES)

    # Echappement HTML : le contenu saisi par l'agent ne doit jamais etre injecte tel quel
    # dans l'email envoye au superviseur (protection contre l'injection HTML).
    nom_affiche = html.escape(payload["nom"])
    poste_affiche = html.escape(payload["poste"])
    raison_affichee = html.escape(raison)
    precision_affichee = html.escape(texte_autre) if texte_autre else "-"

    for sup in superviseurs:
        if not sup["email"]:
            continue

        token_valider = jwt.encode({
            "action": "decision_email", "demande_id": demande_id, "decision": "valider",
            "utilisateur_id": sup["id"], "exp": expiration_lien
        }, CLE_SECRETE, algorithm="HS256")
        token_refuser = jwt.encode({
            "action": "decision_email", "demande_id": demande_id, "decision": "refuser",
            "utilisateur_id": sup["id"], "exp": expiration_lien
        }, CLE_SECRETE, algorithm="HS256")

        lien_valider = f"{IAM_BASE_URL}/decision_email?token={token_valider}"
        lien_refuser = f"{IAM_BASE_URL}/decision_email?token={token_refuser}"

        corps_html = f"""
        <p>{nom_affiche} ({poste_affiche}) demande une prolongation.</p>
        <p><b>Raison :</b> {raison_affichee}<br><b>Precision :</b> {precision_affichee}</p>
        <p>
          <a href="{lien_valider}" style="background:#3ba98c;color:#04140f;padding:10px 18px;
             border-radius:4px;text-decoration:none;font-weight:bold;">Valider</a>
          &nbsp;&nbsp;
          <a href="{lien_refuser}" style="background:#d9534f;color:#fff;padding:10px 18px;
             border-radius:4px;text-decoration:none;font-weight:bold;">Refuser</a>
        </p>
        <p style="color:#8fa5b3;font-size:0.85rem;">
          Le lien ouvre une page de confirmation, cliquer dessus seul ne valide rien.
          Valide {DUREE_VALIDITE_LIEN_EMAIL_HEURES} heures. Demande numero {demande_id}.
        </p>
        """
        envoyer_email(sup["email"], f"Demande de prolongation #{demande_id}", corps_html, html_mode=True)

    return jsonify({"message": "Demande envoyee.", "demande_id": demande_id})


@app.route("/decision_email")
def decision_email():
    """Affiche uniquement une page de confirmation : ne modifie jamais la base sur un simple GET.
    Ca protege contre les scanners de liens automatiques des messageries (Outlook Safe Links, etc.)
    qui suivent tous les liens d'un email sans intervention humaine."""
    token_action = request.args.get("token", "")
    payload, demande, superviseur, erreur = valider_token_decision(token_action)
    if erreur:
        return page_html(erreur, ok=False)

    libelle = "Valider" if payload["decision"] == "valider" else "Refuser"
    return page_confirmation(payload["demande_id"], libelle, token_action)


@app.route("/decision_email/confirmer", methods=["POST"])
def decision_email_confirmer():
    """Seule cette route (POST, declenchee par un vrai clic humain sur le bouton) modifie la base."""
    token_action = request.form.get("token", "")
    payload, demande, superviseur, erreur = valider_token_decision(token_action)
    if erreur:
        return page_html(erreur, ok=False)

    demande_id = payload["demande_id"]
    decision = payload["decision"]
    superviseur_id = payload["utilisateur_id"]

    connexion = get_connexion_bdd()
    # On revalide l'etat "en_attente" juste avant l'ecriture pour eviter une double validation
    # si deux onglets/emails etaient ouverts en meme temps.
    demande_actuelle = connexion.execute(
        "SELECT * FROM demandes_prolongation WHERE id = ?", (demande_id,)
    ).fetchone()
    if demande_actuelle is None or demande_actuelle["statut"] != "en_attente":
        connexion.close()
        statut = demande_actuelle["statut"] if demande_actuelle else "inconnue"
        return page_html(f"Cette demande a deja ete traitee (statut actuel : {statut}).", ok=False)

    heure_traitement = datetime.datetime.now(FUSEAU_BENIN)
    nouveau_statut = "validee" if decision == "valider" else "refusee"

    connexion.execute(
        "UPDATE demandes_prolongation SET statut = ?, traite_par = ?, heure_traitement = ? WHERE id = ?",
        (nouveau_statut, superviseur_id, heure_traitement.isoformat(), demande_id)
    )

    if decision == "valider":
        session_liee = connexion.execute(
            "SELECT * FROM sessions WHERE id = ?", (demande_actuelle["session_id"],)
        ).fetchone()
        nouvelle_expiration = calculer_nouvelle_expiration(session_liee, heure_traitement)
        connexion.execute(
            "UPDATE sessions SET heure_expiration = ?, statut = 'prolongee' WHERE id = ?",
            (nouvelle_expiration.isoformat(), demande_actuelle["session_id"])
        )

    journaliser(
        connexion, superviseur_id, superviseur["nom"],
        "traitement_prolongation", f"demande_id={demande_id}, decision={decision}, via=email"
    )

    connexion.commit()
    connexion.close()

    return page_html(f"Demande #{demande_id} : {nouveau_statut}. Vous pouvez fermer cette page.")


@app.route("/statut_demande", methods=["POST"])
def statut_demande():
    donnees = request.get_json(silent=True) or {}
    payload, erreur, code = authentifier_requete(donnees, "statut_demande")
    if erreur:
        return jsonify({"erreur": erreur}), code

    demande_id = donnees.get("demande_id")
    if not id_valide(demande_id):
        return jsonify({"erreur": "Numero de demande invalide. Il doit s'agir d'un entier positif."}), 400

    connexion = get_connexion_bdd()
    demande = connexion.execute(
        "SELECT d.*, s.utilisateur_id FROM demandes_prolongation d "
        "JOIN sessions s ON s.id = d.session_id WHERE d.id = ?", (demande_id,)
    ).fetchone()
    connexion.close()

    if demande is None:
        return jsonify({"erreur": "Demande introuvable."}), 404

    if payload["role"] == "agent" and demande["utilisateur_id"] != payload["utilisateur_id"]:
        return jsonify({"erreur": "Vous ne pouvez consulter que vos propres demandes."}), 403

    return jsonify({"statut": demande["statut"], "raison": demande["raison"]})


@app.route("/valider_prolongation", methods=["POST"])
def valider_prolongation():
    donnees = request.get_json(silent=True) or {}
    payload, erreur, code = authentifier_requete(donnees, "valider_prolongation")
    if erreur:
        return jsonify({"erreur": erreur}), code

    demande_id = donnees.get("demande_id")
    if not id_valide(demande_id):
        return jsonify({"erreur": "Numero de demande invalide. Il doit s'agir d'un entier positif."}), 400

    decision = donnees.get("decision")
    if decision not in ("valider", "refuser"):
        return jsonify({"erreur": "Decision invalide."}), 400

    connexion = get_connexion_bdd()
    demande = connexion.execute(
        "SELECT * FROM demandes_prolongation WHERE id = ?", (demande_id,)
    ).fetchone()
    if demande is None:
        connexion.close()
        return jsonify({"erreur": "Demande introuvable."}), 404

    if demande["statut"] != "en_attente":
        connexion.close()
        return jsonify({"erreur": "Cette demande a deja ete traitee."}), 409

    session_liee = connexion.execute(
        "SELECT * FROM sessions WHERE id = ?", (demande["session_id"],)
    ).fetchone()
    if session_liee is None:
        connexion.close()
        return jsonify({"erreur": "Session liee introuvable."}), 404

    heure_traitement = datetime.datetime.now(FUSEAU_BENIN)
    nouveau_statut = "validee" if decision == "valider" else "refusee"

    connexion.execute(
        "UPDATE demandes_prolongation SET statut = ?, traite_par = ?, heure_traitement = ? WHERE id = ?",
        (nouveau_statut, payload["utilisateur_id"], heure_traitement.isoformat(), demande_id)
    )

    if decision == "valider":
        nouvelle_expiration = calculer_nouvelle_expiration(session_liee, heure_traitement)
        connexion.execute(
            "UPDATE sessions SET heure_expiration = ?, statut = 'prolongee' WHERE id = ?",
            (nouvelle_expiration.isoformat(), demande["session_id"])
        )

    journaliser(
        connexion, payload["utilisateur_id"], payload["nom"],
        "traitement_prolongation", f"demande_id={demande_id}, decision={decision}, via=application"
    )
    connexion.commit()
    connexion.close()

    return jsonify({"message": f"Demande {nouveau_statut}."})


@app.route("/creer_utilisateur", methods=["POST"])
def creer_utilisateur():
    donnees = request.get_json() or {}
    payload, erreur, code = authentifier_requete(donnees, "creer_utilisateur")
    if erreur:
        return jsonify({"erreur": erreur}), code

    nom = (donnees.get("nom") or "").strip()
    mot_de_passe = donnees.get("mot_de_passe") or ""
    role = donnees.get("role")
    poste = (donnees.get("poste") or "").strip()

    if not nom or not mot_de_passe or not poste:
        return jsonify({"erreur": "Tous les champs sont obligatoires."}), 400
    if not re.match(r"^[A-Za-z0-9_]+$", nom):
        return jsonify({"erreur": "L'identifiant ne doit contenir que lettres, chiffres et underscore."}), 400
    if len(mot_de_passe) < 8:
        return jsonify({"erreur": "Le mot de passe doit contenir au moins 8 caracteres."}), 400
    if role not in ROLES_VALIDES:
        return jsonify({"erreur": "Role invalide."}), 400

    token_expire = 1 if role in ("agent", "chef") else 0
    peut_valider = 1 if role == "superviseur" else 0

    connexion = get_connexion_bdd()
    try:
        connexion.execute(
            "INSERT INTO utilisateurs "
            "(nom, mot_de_passe_hash, role, poste, email, token_expire, peut_valider_prolongation) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (nom, generate_password_hash(mot_de_passe), role, poste, donnees.get("email"), token_expire, peut_valider)
        )
        journaliser(connexion, payload["utilisateur_id"], payload["nom"], "creation_compte", f"nom_cree={nom}, role={role}")
        connexion.commit()
    except sqlite3.IntegrityError:
        connexion.close()
        return jsonify({"erreur": "Cet identifiant existe deja."}), 409
    connexion.close()

    return jsonify({"message": f"Compte '{nom}' cree avec succes."})


@app.route("/modifier_utilisateur", methods=["POST"])
def modifier_utilisateur():
    donnees = request.get_json() or {}
    payload, erreur, code = authentifier_requete(donnees, "modifier_utilisateur")
    if erreur:
        return jsonify({"erreur": erreur}), code

    nom = (donnees.get("nom") or "").strip()
    if not nom:
        return jsonify({"erreur": "Identifiant manquant."}), 400

    connexion = get_connexion_bdd()
    cible = connexion.execute("SELECT * FROM utilisateurs WHERE nom = ?", (nom,)).fetchone()
    if cible is None:
        connexion.close()
        return jsonify({"erreur": "Compte introuvable."}), 404

    nouveau_role = donnees.get("role") or cible["role"]
    nouveau_poste = (donnees.get("poste") or "").strip() or cible["poste"]

    if nouveau_role not in ROLES_VALIDES:
        connexion.close()
        return jsonify({"erreur": "Role invalide."}), 400

    token_expire = 1 if nouveau_role in ("agent", "chef") else 0
    peut_valider = 1 if nouveau_role == "superviseur" else 0

    connexion.execute(
        "UPDATE utilisateurs SET role = ?, poste = ?, token_expire = ?, peut_valider_prolongation = ? "
        "WHERE nom = ?",
        (nouveau_role, nouveau_poste, token_expire, peut_valider, nom)
    )
    journaliser(connexion, payload["utilisateur_id"], payload["nom"], "modification_compte", f"nom_cible={nom}")
    connexion.commit()
    connexion.close()

    return jsonify({"message": f"Compte '{nom}' mis a jour."})


@app.route("/desactiver_utilisateur", methods=["POST"])
def desactiver_utilisateur():
    donnees = request.get_json() or {}
    payload, erreur, code = authentifier_requete(donnees, "desactiver_utilisateur")
    if erreur:
        return jsonify({"erreur": erreur}), code

    nom = (donnees.get("nom") or "").strip()
    connexion = get_connexion_bdd()
    cible = connexion.execute("SELECT id FROM utilisateurs WHERE nom = ?", (nom,)).fetchone()
    if cible is None:
        connexion.close()
        return jsonify({"erreur": "Compte introuvable."}), 404

    if cible["id"] == payload["utilisateur_id"]:
        connexion.close()
        return jsonify({"erreur": "Le RSSI ne peut pas desactiver son propre compte."}), 400

    connexion.execute("UPDATE utilisateurs SET actif = 0 WHERE nom = ?", (nom,))
    journaliser(connexion, payload["utilisateur_id"], payload["nom"], "desactivation_compte", f"nom_cible={nom}")
    connexion.commit()
    connexion.close()

    return jsonify({"message": f"Compte '{nom}' desactive."})


@app.route("/activer_utilisateur", methods=["POST"])
def activer_utilisateur():
    donnees = request.get_json() or {}
    payload, erreur, code = authentifier_requete(donnees, "activer_utilisateur")
    if erreur:
        return jsonify({"erreur": erreur}), code

    nom = (donnees.get("nom") or "").strip()
    if not nom:
        return jsonify({"erreur": "Identifiant manquant."}), 400

    connexion = get_connexion_bdd()
    cible = connexion.execute(
        "SELECT id, nom, actif FROM utilisateurs WHERE nom = ?", (nom,)
    ).fetchone()
    if cible is None:
        connexion.close()
        return jsonify({"erreur": "Compte introuvable."}), 404

    if cible["actif"] == 1:
        connexion.close()
        return jsonify({"erreur": "Ce compte est deja actif."}), 409

    connexion.execute("UPDATE utilisateurs SET actif = 1 WHERE id = ?", (cible["id"],))
    journaliser(
        connexion, payload["utilisateur_id"], payload["nom"],
        "activation_compte", f"nom_cible={nom}"
    )
    connexion.commit()
    connexion.close()

    return jsonify({"message": f"Compte '{nom}' reactive avec succes."})
@app.route("/logout", methods=["POST"])
def logout():
    donnees = request.get_json() or {}

    payload, erreur, code = authentifier_requete(donnees)
    if erreur:
        return jsonify({"erreur": erreur}), code

    connexion = get_connexion_bdd()

    journaliser(
        connexion,
        payload["utilisateur_id"],
        payload["nom"],
        "deconnexion",
        "Déconnexion volontaire"
    )

    connexion.commit()
    connexion.close()

    return jsonify({"message": "Déconnexion enregistrée."})

@app.route("/journal", methods=["POST"])
def journal():
    donnees = request.get_json() or {}
    payload, erreur, code = authentifier_requete(donnees, "journal")
    if erreur:
        return jsonify({"erreur": erreur}), code

    connexion = get_connexion_bdd()
    lignes = connexion.execute(
        "SELECT nom_utilisateur, action, details, heure FROM journal_activite "
        "ORDER BY heure DESC LIMIT 100"
    ).fetchall()
    connexion.close()

    resultat = [
        {"nom": l["nom_utilisateur"], "action": l["action"], "details": l["details"], "heure": l["heure"]}
        for l in lignes
    ]
    return jsonify({"entrees": resultat})


if __name__ == "__main__":
    debug = os.environ.get("IAM_DEBUG", "0") == "1"
    if debug:
        print("[ATTENTION] Mode debug active : ne JAMAIS exposer ce serveur a Internet (ngrok, etc.) dans cet etat.")
        print("[ATTENTION] Le debogueur Werkzeug permet l'execution de code arbitraire a distance en mode debug.")
    app.run(debug=False, host="0.0.0.0", port=5000)