import subprocess
import json
from typing import List, Dict
import tempfile
import logging

def run_bandit_scan(target_path: str, severity_level: str = "low", ignored_tests: List[str] = []) -> List[Dict[str, str]]:
    """
    Exécute Bandit sur le code source du projet.
    :param target_path: Chemin vers le dossier à analyser
    :param severity_level: Niveau de sévérité minimum (low, medium, high)
    :param ignored_tests: Liste des tests à ignorer (ex: ['B101'])
    :return: Liste de résultats de l'analyse
    """
    cmd = [
        "bandit", "-r", target_path,
        "--severity-level", severity_level,
        "--format", "json"
    ]

    if ignored_tests:
        cmd.extend(["--skip", ",".join(ignored_tests)])

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmpfile:
        cmd.extend(["-o", tmpfile.name])

        try:
            result = subprocess.run(cmd, check=False)
            if result.returncode > 1:
                logging.error(f"[Bandit] Erreur d'exécution : {result}")
                raise RuntimeError(f"Erreur critique de Bandit : code {result.returncode}")
            with open(tmpfile.name, "r", encoding="utf-8") as result_file:
                results = json.load(result_file)
                return results.get("results", [])
        except FileNotFoundError:
            raise RuntimeError("Bandit n'est pas installé. Installez-le avec : pip install bandit")
