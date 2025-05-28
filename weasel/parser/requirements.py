import re
import os
import subprocess
from pathlib import Path
from typing import List, Dict
from packaging.requirements import Requirement
import chardet
import json
import requests

# ——— Cache des métadonnées PyPI ———
PYPICACHE = os.path.expanduser("weasel_cache/pypi_metadata.json")

def _load_pypi_cache():
    if os.path.isfile(PYPICACHE):
        with open(PYPICACHE, "r") as f:
            return json.load(f)
    return {}

def _save_pypi_cache(cache):
    os.makedirs(os.path.dirname(PYPICACHE), exist_ok=True)
    with open(PYPICACHE, "w") as f:
        json.dump(cache, f, indent=2)
 
def get_package_author(pkg_name: str) -> str:
    """
    Récupère le champ 'author' depuis l'API PyPI (cache à ~/.weasel_cache/pypi_metadata.json).
    """
    cache = _load_pypi_cache()
    if pkg_name in cache:
        return cache[pkg_name]

    url = f"https://pypi.org/pypi/{pkg_name}/json"
    author = ""
    try:
        resp = requests.get(url, timeout=10)
        if resp.ok:
            info = resp.json().get("info", {})
            author = info.get("author", "") or info.get("maintainer", "")
    except Exception:
        pass

    cache[pkg_name] = author
    _save_pypi_cache(cache)
    return author
       
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



def compute_full_origins(requirements_path: Path) -> Dict[str, str]:
    """
    Construit pour chaque package la liste de tous les chemins depuis
    les dépendances directes. Renvoie un dict { pkg: "root -> ... -> pkg; ..." }.
    """
    # 1) Récupère la liste des dépendances directes
    from weasel.parser.requirements import parse_requirements
    direct = [r["name"] for r in parse_requirements(requirements_path)]

    # 2) Charge l'arbre plat de pipdeptree
    raw = subprocess.run(
        ["pipdeptree", "--json"],
        check=True, stdout=subprocess.PIPE, text=True
    )
    tree = json.loads(raw.stdout)

    # 3) Construit le graphe d’adjacence parent -> [enfants]
    graph: Dict[str, List[str]] = {}
    for node in tree:
        parent = node["package"]["package_name"]
        deps = []
        for dep in node.get("dependencies", []):
            # certains pipdeptree renvoient enfant sous forme plate
            name = dep.get("package_name") or dep.get("key")
            if name:
                deps.append(name)
        graph[parent] = deps

    # 4) DFS depuis chaque root pour accumuler tous les chemins
    origins: Dict[str, List[List[str]]] = {}
    def dfs(curr: str, path: List[str]):
        origins.setdefault(curr, []).append(path.copy())
        for child in graph.get(curr, []):
            if child in path:
                continue  # éviter les cycles
            dfs(child, path + [child])

    for root in direct:
        dfs(root, [root])

    # 5) Formate en chaînes séparées par ;
    return {
        pkg: "; ".join(" -> ".join(p) for p in paths)
        for pkg, paths in origins.items()
    }