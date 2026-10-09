"""
init_db.py - Cree la base de donnees SQLite du projet IAM
"""

import sqlite3
from werkzeug.security import generate_password_hash

connexion = sqlite3.connect("database.db")
curseur = connexion.cursor()

curseur.execute("""
CREATE TABLE IF NOT EXISTS utilisateurs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT NOT NULL UNIQUE,
    mot_de_passe_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('agent', 'chef', 'superviseur', 'admin')),
    poste TEXT NOT NULL,
    email TEXT,
    token_expire INTEGER NOT NULL DEFAULT 1,
    peut_valider_prolongation INTEGER NOT NULL DEFAULT 0,
    actif INTEGER NOT NULL DEFAULT 1
)
""")

curseur.execute("""
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    utilisateur_id INTEGER NOT NULL,
    heure_debut TEXT NOT NULL,
    heure_expiration TEXT NOT NULL,
    statut TEXT NOT NULL DEFAULT 'actif',
    FOREIGN KEY (utilisateur_id) REFERENCES utilisateurs(id)
)
""")

curseur.execute("""
CREATE TABLE IF NOT EXISTS demandes_prolongation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    heure_demande TEXT NOT NULL,
    raison TEXT NOT NULL CHECK(raison IN ('incident', 'maintenance', 'retard_taches', 'autre')),
    texte_autre TEXT,
    statut TEXT NOT NULL DEFAULT 'en_attente',
    traite_par INTEGER,
    heure_traitement TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id),
    FOREIGN KEY (traite_par) REFERENCES utilisateurs(id)
)
""")

# Journal des activites
curseur.execute("""
CREATE TABLE IF NOT EXISTS journal_activite (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    utilisateur_id INTEGER,
    action TEXT NOT NULL,
    description TEXT,
    heure TEXT NOT NULL,
    FOREIGN KEY (utilisateur_id) REFERENCES utilisateurs(id)
)
""")

connexion.commit()

utilisateurs_de_depart = [
    ("agent1", "motdepasse1", "agent", "Technicien de site de Diffusion", None, 1, 0),
    ("agent2", "motdepasse2", "agent", "Technicien de site de Diffusion", None, 1, 0),
    ("agent3", "motdepasse3", "agent", "Technicien de site de Diffusion", None, 1, 0),
    ("agent4", "motdepasse4", "agent", "Technicien de site de Diffusion", None, 1, 0),
    ("chef1", "motdepasse5", "chef", "Chef Service d'Exploitation National", None, 0, 0),
    ("chef2", "motdepasse6", "chef", "Responsable de Maintenance Regionale", None, 0, 0),
    ("superviseur1", "motdepasse7", "superviseur", "Chef Site de Diffusion", "superviseur@gmail.com", 0, 1),
    ("rssi_admin", "motdepasse8", "admin", "RSSI", None, 0, 0),
]

for nom, mdp, role, poste, email, token_expire, peut_valider in utilisateurs_de_depart:
    mdp_hash = generate_password_hash(mdp)
    try:
        curseur.execute(
            "INSERT INTO utilisateurs (nom, mot_de_passe_hash, role, poste, email, token_expire, peut_valider_prolongation) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (nom, mdp_hash, role, poste, email, token_expire, peut_valider)
        )
    except sqlite3.IntegrityError:
        pass

connexion.commit()
connexion.close()

print("Base de donnees mise a jour avec succes : database.db")
print("8 comptes de test sont disponibles.")