"""import json
from pipdeptree import get_installed_distributions, build_dist_index, construct_tree
from pyvis.network import Network
import os


def generate_dependency_graph(output_path="dependency_graph.html"):
    """
    Génère un graphe de dépendances interactif à partir de l'environnement Python courant.
    """
    dists = get_installed_distributions()
    dist_index = build_dist_index(dists)
    tree = construct_tree(dist_index)

    net = Network(height="800px", width="100%", directed=True, notebook=False)
    net.barnes_hut()

    added = set()

    for parent, children in tree.items():
        parent_name = parent.project_name

        if parent_name not in added:
            net.add_node(parent_name, label=parent_name)
            added.add(parent_name)

        for child in children:
            child_name = child.project_name

            if child_name not in added:
                net.add_node(child_name, label=child_name)
                added.add(child_name)

            net.add_edge(parent_name, child_name)

    net.show_buttons(filter_=['physics'])  # permet d'ajuster la disposition du graphe
    net.show(output_path)
    print(f"🧠 Graphe généré : {os.path.abspath(output_path)}")
"""