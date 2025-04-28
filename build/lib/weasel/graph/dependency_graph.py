from pyvis.network import Network
from typing import List, Dict
from pathlib import Path
import subprocess
import json
import logging


def generate_dependency_graph(packages: List[Dict], vulnerable_packages: List[str], output_file: str):
    """
    Génère un graphe HTML interactif des dépendances à partir de l'arbre de pipdeptree
    :param packages: Liste de paquets installés (utilisé uniquement pour colorer les nœuds)
    :param vulnerable_packages: Liste des noms de paquets vulnérables
    :param output_file: Chemin de sortie du fichier HTML généré
    """
    net = Network(height='700px', width='100%', bgcolor='#ffffff', font_color='black')
    net.force_atlas_2based()

    package_versions = {pkg["name"]: pkg.get("version", "") for pkg in packages}
    all_nodes = set()

    try:
        result = subprocess.run(["pipdeptree", "--json"], capture_output=True, check=True, text=True)
        tree_data = json.loads(result.stdout)
    except FileNotFoundError:
        logging.error("pipdeptree n'est pas installé. Installez-le avec : pip install pipdeptree")
        return
    except subprocess.CalledProcessError as e:
        logging.error(f"Erreur lors de l'exécution de pipdeptree : {e.stderr}")
        return

    # Ajout des nœuds et des liens à partir de la hiérarchie réelle
    for entry in tree_data:
        parent = entry["package"]["key"]
        version = package_versions.get(parent, "")
        label = f"{parent}\n{version}" if version else parent
        color = "#ff4d4d" if parent in vulnerable_packages else "#4dff88"

        net.add_node(parent, label=label, color=color)
        all_nodes.add(parent)

        for dep in entry.get("dependencies", []):
            child = dep["key"]
            if child not in all_nodes:
                child_version = package_versions.get(child, "")
                child_label = f"{child}\n{child_version}" if child_version else child
                child_color = "#ff4d4d" if child in vulnerable_packages else "#4dff88"
                net.add_node(child, label=child_label, color=child_color)
                all_nodes.add(child)
            net.add_edge(parent, child)

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    net.show(output_file)
