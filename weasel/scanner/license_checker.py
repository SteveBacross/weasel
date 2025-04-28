import subprocess
import json
import logging
from pathlib import Path
from typing import List, Dict

CACHE_FILE = Path.home() / ".weasel_cache" / "licenses.json"
CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

def get_licenses(offline: bool = False) -> List[Dict[str, str]]:
    """
    Récupère les licences via pip-licenses, ou depuis un cache local en mode offline
    :param offline: Si True, lit les données depuis un cache local
    :return: Liste brute des données de licence
    """
    if offline:
        if CACHE_FILE.exists():
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logging.warning("Fichier de cache des licences corrompu.")
                return []
        else:
            logging.warning("Aucun cache local de licences trouvé.")
            return []

    try:
        result = subprocess.run(
            ["pip-licenses", "--format=json", "--with-authors", "--with-license-file", "--with-notice"],
            capture_output=True,
            check=True,
            text=True
        )
        data = json.loads(result.stdout)
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return data
    except FileNotFoundError:
        raise RuntimeError("pip-licenses n'est pas installé. Utilisez : pip install pip-licenses")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Erreur d'exécution pip-licenses : {e.stderr}")

def simplify_license_info(license_data: List[Dict[str, str]]) -> List[Dict[str, str]]:
    result = []
    for pkg in license_data:
        level = classify_license(pkg.get("License", ""))
        result.append({
            "name": pkg.get("Name"),
            "license": pkg.get("License"),
            "author": pkg.get("Author", ""),
            "license_file": pkg.get("LicenseFile", ""),
            "notice": pkg.get("NoticeFile", ""),
            "permissivity": level
        })
    return result

def classify_license(license_name: str) -> str:
    permissive = ["MIT", "BSD", "Apache", "ISC"]
    restrictive = ["GPL", "AGPL", "LGPL"]

    if any(x in license_name for x in permissive):
        return "permissive"
    elif any(x in license_name for x in restrictive):
        return "restrictive"
    elif license_name.strip():
        return "unknown"
    else:
        return "none"
