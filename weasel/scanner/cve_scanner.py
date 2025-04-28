import requests
import hashlib
import os
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional

OSV_API_URL = "https://api.osv.dev/v1/query"
CACHE_DIR = Path.home() / ".weasel_cache" / "osv"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

def _cache_key(package: str, version: str) -> Path:
    key = hashlib.sha256(f"{package}=={version}".encode()).hexdigest()
    return CACHE_DIR / f"{key}.json"

def _load_from_cache(package: str, version: str) -> Optional[Dict]:
    cache_file = _cache_key(package, version)
    if cache_file.exists():
        try:
            with open(cache_file, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            logging.warning(f"Fichier de cache corrompu pour {package}=={version}")
    return None

def _save_to_cache(package: str, version: str, data: Dict):
    cache_file = _cache_key(package, version)
    with open(cache_file, "w") as f:
        json.dump(data, f)

def get_cve_for_package(package: str, version: str, offline: bool = False) -> List[Dict]:
    if offline:
        cached = _load_from_cache(package, version)
        return cached.get("vulns", []) if cached else []

    payload = {
        "package": {
            "name": package,
            "ecosystem": "PyPI"
        },
        "version": version
    }

    try:
        response = requests.post(OSV_API_URL, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        _save_to_cache(package, version, data)
        return data.get("vulns", [])
    except Exception as e:
        logging.error(f"Échec de la requête OSV pour {package}=={version} : {e}")
        return []

def format_cve(cve: Dict) -> Dict:
    return {
        "id": cve.get("id"),
        "summary": cve.get("summary"),
        "severity": _extract_severity(cve),
        "cvss_score": _extract_cvss(cve),
        "references": [ref["url"] for ref in cve.get("references", []) if isinstance(ref, dict) and "url" in ref],
        "source": "OSV"
    }

def _extract_cvss(cve: Dict) -> Optional[float]:
    scores = cve.get("severity", [])
    for item in scores:
        if item.get("type") == "CVSS_V3":
            try:
                return float(item.get("score"))
            except (ValueError, TypeError):
                pass
    return None

def _extract_severity(cve: Dict) -> str:
    score = _extract_cvss(cve)
    if score is None:
        return "unknown"
    if score < 4.0:
        return "low"
    elif score < 7.0:
        return "medium"
    elif score < 9.0:
        return "high"
    else:
        return "critical"
