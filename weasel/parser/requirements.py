import re
import subprocess
from pathlib import Path
from typing import List, Dict
from packaging.requirements import Requirement
import chardet

def detect_encoding(file_path: Path) -> str:
    with open(file_path, "rb") as f:
        raw_data = f.read(4096)
    result = chardet.detect(raw_data)
    return result["encoding"] or "utf-8"

def parse_requirements(requirements_path: Path) -> List[Dict[str, str]]:
    """
    Analyse un fichier requirements.txt et retourne une liste de dépendances formatées
    :param requirements_path: Chemin vers le fichier requirements.txt
    :return: Liste de dictionnaires avec nom, version (specifier) et ligne originale
    """
    dependencies = []
    encoding = detect_encoding(requirements_path)

    with requirements_path.open("r", encoding=encoding) as f:
        for idx, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                req = Requirement(line)
                dependencies.append({
                    "name": req.name,
                    "specifier": str(req.specifier) if req.specifier else "",
                    "line": line
                })
            except Exception as e:
                import logging
                logging.warning(f"Ligne {idx} ignorée : '{line}' ({e})")

    return dependencies

def resolve_all_dependencies(requirements_path: Path) -> List[Dict[str, str]]:
    """
    Installe les dépendances dans un environnement temporaire et résout les dépendances transitives
    :param requirements_path: Chemin vers le fichier requirements.txt
    :return: Liste complète de packages installés avec version exacte
    """
    import tempfile
    import venv
    import os
    import json

    with tempfile.TemporaryDirectory() as tmpdir:
        env_dir = Path(tmpdir) / "venv"
        venv.create(env_dir, with_pip=True)

        python_bin = env_dir / "bin" / "python" if os.name != "nt" else env_dir / "Scripts" / "python.exe"
        pip_bin = [str(python_bin), "-m", "pip"]

        subprocess.run(pip_bin + ["install", "--quiet", "-r", str(requirements_path)], check=True)

        result = subprocess.run(pip_bin + ["list", "--format", "json"], capture_output=True, check=True)
        packages = json.loads(result.stdout)

        return packages
