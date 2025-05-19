SIDEBAR_HTML = """
<div id="sidebar">
  <input type="text" id="searchInput" placeholder="🔍 Rechercher un package..." oninput="filterNodes()">
  <label><input type="checkbox" id="vulnOnly" onchange="filterNodes()"> Afficher seulement les vulnérables</label>
  <hr>
  <div class="info-block" id="nodeInfo">
    <h3>Détails</h3>
    <p>Cliquez sur un nœud pour voir les infos ici.</p>
  </div>
</div>
<style>
  #sidebar {
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
  }
  #sidebar h3 { margin-top: 0; }
  .info-block { margin-bottom: 10px; }
  input[type="text"] {
    width: 100%;
    padding: 6px;
    margin-bottom: 10px;
    border-radius: 4px;
    border: none;
  }
  label {
    display: block;
    margin-top: 10px;
  }
</style>
"""

SIDEBAR_JS = """
<script>
  function filterNodes() {
    var input = document.getElementById("searchInput").value.toLowerCase();
    var vulnOnly = document.getElementById("vulnOnly").checked;
    network.body.data.nodes.forEach(function(node) {
      const match = node.label.toLowerCase().includes(input);
      const isVuln = node.group === "vuln";
      node.hidden = (vulnOnly && !isVuln) || !match;
    });
  }

  network.on("click", function(params) {
    if (params.nodes.length > 0) {
      var nodeId = params.nodes[0];
      var node = network.body.data.nodes.get(nodeId);
      fetchNodeData(nodeId).then(info => {
        var html = `
          <h3>${node.label}</h3>
          <p><b>Version :</b> ${info.version}</p>
          <p><b>Vulnérable :</b> ${info.vuln ? "Oui" : "Non"}</p>
          <p><b>Dépend de :</b> ${info.deps.length}</p>
          <p><b>Utilisé par :</b> ${info.dependents.length}</p>
        `;
        document.getElementById("nodeInfo").innerHTML = html;
      });
    }
  });

  async function fetchNodeData(id) {
    const data = {{node_info}};
    return data[id];
  }

  network.once("afterDrawing", () => {
    network.fit({ animation: true });
  });
</script>
"""
