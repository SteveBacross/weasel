from pathlib import Path
import json
import subprocess
import logging


def generate_dependency_graph_dash(output_file: Path, vulnerable_packages: list):
    """
    Génère une version HTML interactive d’un graphe de dépendances avec Dash (via dash-cytoscape)
    """
    try:
        result = subprocess.run(["pipdeptree", "--json"], capture_output=True, text=True, check=True)
        tree_data = json.loads(result.stdout)
    except Exception as e:
        logging.error(f"Erreur lors de l'exécution de pipdeptree : {e}")
        return

    # Construction des noeuds et liens
    nodes = {}
    edges = []

    for entry in tree_data:
        parent = entry["package"]["key"]
        version = entry["package"].get("installed_version", "")
        is_vuln = parent in vulnerable_packages
        color = "#ff4d4d" if is_vuln else "#4dff88"

        nodes[parent] = {
            "data": {
                "id": parent,
                "label": f"{parent}\\n{version}",
                "tooltip": f"{parent} {version}",
                "color": color
            }
        }

        for dep in entry.get("dependencies", []):
            child = dep["key"]
            edges.append({"data": {"source": parent, "target": child}})

    cytoscape_elements = list(nodes.values()) + edges

    html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Dash Dependency Graph</title>
    <script src="https://unpkg.com/react@17/umd/react.development.js"></script>
    <script src="https://unpkg.com/react-dom@17/umd/react-dom.development.js"></script>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <script src="https://unpkg.com/dash-cytoscape@0.3.0/dash_cytoscape.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/dash-html-components@1.1.4/dash_html_components.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/dash@2.12.1/dash.min.js"></script>
    <style>
        #sidebar {{ position: absolute; top: 20px; left: 20px; background: #fff; padding: 10px; border-radius: 5px; width: 250px; }}
        #cytoscape {{ width: 100vw; height: 100vh; }}
    </style>
</head>
<body>
    <div id="sidebar">
        <h3>Détails du noeud</h3>
        <pre id="node-details">Cliquez sur un noeud...</pre>
    </div>
    <div id="cytoscape"></div>
    <script src="https://unpkg.com/cytoscape/dist/cytoscape.min.js"></script>
    <script>
        const elements = {json.dumps(cytoscape_elements)};

        const cy = window.cy = cytoscape({{
            container: document.getElementById('cytoscape'),
            elements: elements,
            style: [
                {{ selector: 'node', style: {{
                    'background-color': 'data(color)',
                    'label': 'data(label)',
                    'text-valign': 'center',
                    'color': 'black',
                    'font-size': '10px'
                }} }},
                {{ selector: 'edge', style: {{
                    'width': 2,
                    'line-color': '#ccc',
                    'target-arrow-color': '#ccc',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier'
                }} }}
            ],
            layout: {{
                name: 'breadthfirst',
                directed: true,
                padding: 10,
                spacingFactor: 1.5,
                animate: false,
                orientation: 'horizontal'
            }}
        }});

        cy.on('tap', 'node', function(evt) {{
            var node = evt.target;
            document.getElementById("node-details").textContent = JSON.stringify(node.data(), null, 2);
        }});
    </script>
</body>
</html>
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(html_template, encoding="utf-8")
