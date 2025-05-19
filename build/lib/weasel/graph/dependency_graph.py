from pyvis.network import Network
from typing import List, Dict
from pathlib import Path
import subprocess
import json
import logging


def generate_dependency_graph(packages: List[Dict], vulnerable_packages: List[str], output_file: str):
    net = Network(
        height="800px",
        width="100%",
        bgcolor="#111111",
        font_color="white",
        directed=True
    )

    net.set_options("""
    var options = {
      "layout": {
        "hierarchical": {
          "enabled": true,
          "sortMethod": "directed",
          "direction": "LR",
          "nodeSpacing": 200,
          "treeSpacing": 300
        }
      },
      "physics": {
        "enabled": false
      },
      "edges": {
        "arrows": {
          "to": { "enabled": true, "scaleFactor": 0.7 }
        },
        "smooth": {
          "enabled": true,
          "type": "cubicBezier",
          "roundness": 0.6
        },
        "color": { "color": "#aaaaaa" }
      },
      "nodes": {
        "shape": "dot",
        "size": 18,
        "font": { "size": 18 }
      },
      "interaction": {
        "hover": true,
        "tooltipDelay": 100
      }
    }
    """)

    package_versions = {pkg["name"].lower(): pkg.get("version", "") for pkg in packages}
    all_nodes = set()
    node_info = {}

    try:
        result = subprocess.run(["pipdeptree", "--json"], capture_output=True, check=True, text=True)
        tree_data = json.loads(result.stdout)
    except FileNotFoundError:
        logging.error("pipdeptree n'est pas installé. Installez-le avec : pip install pipdeptree")
        return
    except subprocess.CalledProcessError as e:
        logging.error(f"Erreur lors de l'exécution de pipdeptree : {e.stderr}")
        return

    # Map inverse pour reverse deps
    reverse_deps = {}

    for entry in tree_data:
        parent = entry["package"]["key"].lower()
        version = package_versions.get(parent, "")
        is_vuln = parent in vulnerable_packages
        deps = [dep["key"].lower() for dep in entry.get("dependencies", [])]

        node_info[parent] = {
            "name": parent,
            "version": version,
            "vuln": is_vuln,
            "deps": deps,
            "dependents": []  # à remplir plus tard
        }

        for dep in deps:
            reverse_deps.setdefault(dep, []).append(parent)

    for pkg, info in node_info.items():
        dependents = reverse_deps.get(pkg, [])
        info["dependents"] = dependents

        label = f"{pkg}@{info['version']}" if info["version"] else pkg
        tooltip = f"{pkg} v{info['version']}" if info["version"] else pkg
        color = "#ff4d4d" if info["vuln"] else "#4dff88"

        net.add_node(pkg, label=label, title=tooltip, color=color, group="vuln" if info["vuln"] else "safe")
        all_nodes.add(pkg)

        for dep in info["deps"]:
            if dep not in all_nodes:
                dep_version = package_versions.get(dep, "")
                dep_color = "#ff4d4d" if dep in vulnerable_packages else "#4dff88"
                dep_label = f"{dep}@{dep_version}" if dep_version else dep
                net.add_node(dep, label=dep_label, title=dep, color=dep_color,
                             group="vuln" if dep in vulnerable_packages else "safe")
                all_nodes.add(dep)

            net.add_edge(pkg, dep)

    # Création du fichier HTML de base
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    net.write_html(output_file)

    # Injecter le JS/CSS pour sidebar + filtres
    with open(output_file, "r", encoding="utf-8") as f:
        html = f.read()

    custom_ui = f"""
    <style>
      #sidebar {{
        position: absolute;
        top: 10px;
        left: 10px;
        width: 300px;
        background: #222;
        color: white;
        padding: 15px;
        border-radius: 8px;
        z-index: 100;
        font-family: sans-serif;
        font-size: 14px;
      }}
      #sidebar h3 {{ margin-top: 0; }}
      .info-block {{ margin-bottom: 10px; }}
      input[type="text"] {{
        width: 100%;
        padding: 6px;
        margin-bottom: 10px;
        border-radius: 4px;
        border: none;
      }}
      label {{
        display: block;
        margin-top: 10px;
      }}
    </style>

    <div id="sidebar">
      <input type="text" id="searchInput" placeholder="🔍 Rechercher un package..." oninput="filterNodes()">
      <label><input type="checkbox" id="vulnOnly" onchange="filterNodes()"> Afficher seulement les vulnérables</label>
      <hr>
      <div class="info-block" id="nodeInfo">
        <h3>Détails</h3>
        <p>Cliquez sur un nœud pour voir les infos ici.</p>
      </div>
    </div>

    <script>
      function filterNodes() {{
        var input = document.getElementById("searchInput").value.toLowerCase();
        var vulnOnly = document.getElementById("vulnOnly").checked;
        network.body.data.nodes.forEach(function(node) {{
          const match = node.label.toLowerCase().includes(input);
          const isVuln = node.group === "vuln";
          node.hidden = (vulnOnly && !isVuln) || !match;
        }});
      }}

      network.on("click", function(params) {{
        if (params.nodes.length > 0) {{
          var nodeId = params.nodes[0];
          var node = network.body.data.nodes.get(nodeId);
          var nodeData = {json.dumps(node_info)};
          var info = nodeData[nodeId];
          var html = `
            <h3>${{node.label}}</h3>
            <p><b>Version :</b> ${{info.version}}</p>
            <p><b>Vulnérable :</b> ${{info.vuln ? "Oui" : "Non"}}</p>
            <p><b>Dépend de :</b> ${{info.deps.length}}</p>
            <p><b>Utilisé par :</b> ${{info.dependents.length}}</p>
          `;
          document.getElementById("nodeInfo").innerHTML = html;
        }}
      }});
    </script>
    """

    html = html.replace("<body>", "<body>\n" + custom_ui)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
