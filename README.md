# 🛡️ Weasel - Analyse de sécurité pour projets Python

**Weasel** est un outil CLI complet permettant d'analyser un projet Python à partir de son fichier `requirements.txt`.

Il identifie :
- Les vulnérabilités connues (CVE)
- Les types de licences (et leur permissivité)
- Les mauvaises pratiques dans le code (type Bandit)
- Les dépendances sous forme de graphe interactif
- Des rapports exploitables : HTML interactif, PDF, JSON

---

## 🚀 Installation

```bash
# Clone du repo (si nécessaire)
git clone https://github.com/ton-org/weasel.git
cd weasel

# Installation du package
pip install .
```

---

## 🧪 Utilisation

```bash
weasel scan -r requirements.txt [OPTIONS]
```

### Options disponibles :
- `--cve` : analyse les CVEs connues
- `--licenses` : extrait les licences et niveaux de permissivité
- `--code-check` : scanne les mauvaises pratiques avec Bandit
- `--graph` : génère un graphe HTML des dépendances
- `--report-format` : `html`, `json`, ou `pdf`
- `--output` : répertoire de sortie (par défaut : `weasel_report/`)
- `--offline` : utilise le cache local pour les CVEs/licences

### Exemple complet :
```bash
weasel run -r requirements.txt --cve --licenses --code-check --graph --report-format html --config config.yaml



```

---

## 📦 Dépendances principales
- `typer` (CLI)
- `requests` (requêtes API)
- `pip-licenses`, `bandit`, `pyvis`, `weasyprint`
- `jinja2` pour le template HTML

---

## 📄 Rapport généré
- Interactif en HTML (avec recherches dynamiques)
- Exportable en PDF et JSON lisibles

---

## 🧪 Tests

Lance les tests avec :
```bash
pytest tests/
```

---

## 🛠️ À venir
- Mode CI/CD
- Intégration dans GitHub Actions
- Analyse multi-fichiers `requirements.txt`

---

## 📜 Licence
MIT - libre pour usage personnel, académique et professionnel.
