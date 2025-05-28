from pathlib import Path
import json
import subprocess
import logging

def generate_dependency_graph_dash(
    output_file: Path,
    resolved_packages: list,
    direct_packages: list,
    vulnerabilities_map: dict
):
    """
    Génère une version HTML interactive d’un graphe de dépendances avec Cytoscape.js

    - resolved_packages : liste de dicts {name, version, author, origin}
    - direct_packages   : liste de noms de paquets déclarés directement
    - vulnerabilities_map : dict { package_name: [ {id, summary, references, ...}, ... ] }
    """
    try:
        result = subprocess.run(
            ["pipdeptree", "--json"],
            capture_output=True, text=True, check=True
        )
        tree_data = json.loads(result.stdout)
    except Exception as e:
        logging.error(f"Erreur pipdeptree : {e}")
        return

    # Normalisation pour matching case-insensitive
    pkg_map    = {pkg["name"].lower(): pkg for pkg in resolved_packages}
    direct_set = {name.lower() for name in direct_packages}
    vuln_map   = {name.lower(): vulns for name, vulns in vulnerabilities_map.items()}

    nodes = {}
    edges = []

    for entry in tree_data:
        raw_name = entry["package"]["package_name"]
        key      = raw_name.lower()

        info    = pkg_map.get(key, {})
        version = info.get("version", "")
        author  = info.get("author", "–")
        origin  = info.get("origin", "–")

        is_direct = key in direct_set
        is_vuln   = key in vuln_map

        # Choix de la couleur
        if is_vuln:
            color = "#ff4d4d"  # rouge = vulnérable
        elif is_direct:
            color = "#4d79ff"  # bleu = direct
        else:
            color = "#cccccc"  # gris = transitif

        vuln_list = vuln_map.get(key, [])

        nodes[raw_name] = {
            "data": {
                "id": raw_name,
                "label": f"{raw_name}\\n{version}",
                "name": raw_name,
                "version": version,
                "author": author,
                "origin": origin,
                "pypi_url": f"https://pypi.org/project/{raw_name}/",
                "vulnerable": is_vuln,
                "vulnerabilities": vuln_list,
                "color": color
            }
        }

        for dep in entry.get("dependencies", []):
            child = dep.get("package_name") or dep.get("key")
            if child:
                edges.append({"data": {"source": raw_name, "target": child}})

    elements = list(nodes.values()) + edges

    html_template = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Weasel Dependency Graph</title>
  <script src="https://unpkg.com/cytoscape/dist/cytoscape.min.js"></script>
  <style>
    body {{ margin:0; padding:0; overflow:hidden; }}
    #cytoscape {{ width:100vw; height:100vh; }}
    #sidebar {{
      position:absolute; top:20px; left:20px;
      background:rgba(255,255,255,0.95); padding:15px;
      border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,0.2);
      width:280px; max-height:90vh; overflow-y:auto;
      font-family:sans-serif;
    }}
    #controls {{
      position:absolute; top:20px; right:20px;
      background:rgba(255,255,255,0.9); padding:10px;
      border-radius:6px; box-shadow:0 2px 6px rgba(0,0,0,0.15);
      font-family:sans-serif;
    }}
    #controls select, #controls button {{ margin:5px; padding:5px 8px; }}
    #sidebar h3 {{ margin-top:0; }}
    #node-details p {{ margin:4px 0; }}
    #node-details a {{ color:#1f77b4; text-decoration:none; }}
  </style>
</head>
<body>
  <div id="sidebar">
    <h3>Détails du paquet</h3>
    <div id="node-details"><p>Cliquez sur un noeud pour voir les détails.</p></div>
  </div>
  <div id="controls">
    <label for="layout-select">Layout:</label>
    <select id="layout-select">
      <option value="breadthfirst">Breadthfirst</option>
      <option value="cose">COSE</option>
      <option value="circle">Circle</option>
      <option value="concentric">Concentric</option>
      <option value="grid">Grid</option>
    </select>
    <button id="filter-vuln">Montrer seulement les vulnérables</button>
    <button id="reset-btn">Tout réinitialiser</button>
  </div>
  <div id="cytoscape"></div>
  <script>
    const elements = {json.dumps(elements)};
    const cy = cytoscape({{
      container: document.getElementById('cytoscape'),
      elements: elements,
      style: [
        {{ selector: 'node', style: {{
          'background-color': 'data(color)',
          'label': 'data(label)',
          'text-valign': 'center',
          'text-wrap': 'wrap',
          'color': '#000',
          'font-size': '10px'
        }} }},
        {{ selector: 'edge', style: {{
          'width': 2,
          'line-color': '#aaa',
          'target-arrow-color': '#aaa',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier'
        }} }}
      ],
      layout: {{ name:'breadthfirst', directed:true, padding:20, spacingFactor:1.2 }}
    }});

    cy.on('tap', 'node', function(evt) {{
      const d = evt.target.data();
      let html = `
        <h4>${{d.name}}</h4>
        <p><strong>Version:</strong> ${{d.version}}</p>
        <p><strong>Auteur:</strong> ${{d.author}}</p>
        <p><strong>Origine:</strong> ${{d.origin}}</p>
        <p><a href='${{d.pypi_url}}' target='_blank'>Page PyPI</a></p>
        <p><strong>Vulnérabilités:</strong></p>
        <ul>
      `;
      (d.vulnerabilities||[]).forEach(v => {{
        const url = (v.references && v.references[0]) ? v.references[0] : '#';
        html += `<li>${{v.id}} - <a href='${{url}}' target='_blank'>Lien</a></li>`;
      }});
      html += '</ul>';
      document.getElementById('node-details').innerHTML = html;
    }});

    let filterOn = false;
    document.getElementById('filter-vuln').addEventListener('click', function() {{
      if (!filterOn) {{
        cy.nodes().filter(n => !n.data('vulnerable')).hide();
        filterOn = true;
        this.textContent = 'Montrer tout';
      }} else {{
        cy.elements().show();
        filterOn = false;
        this.textContent = 'Montrer seulement les vulnérables';
      }}
    }});

    document.getElementById('reset-btn').addEventListener('click', function() {{
      cy.elements().show();
      cy.layout({{ name: document.getElementById('layout-select').value, directed:true, padding:20, spacingFactor:1.2 }}).run();
    }});

    document.getElementById('layout-select').addEventListener('change', function() {{
      cy.layout({{ name: this.value, directed:true, padding:20, spacingFactor:1.2 }}).run();
    }});
  </script>
</body>
</html>
"""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(html_template, encoding='utf-8')
