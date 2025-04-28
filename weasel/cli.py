import typer
from weasel.commands.run import run_scan
from weasel.commands.about import about

app = typer.Typer(help="Weasel - Outil d'analyse de sécurité pour projets Python")

# Ajout de la sous-commande "run"
app.command(name="run")(run_scan)

# Optionnel : une commande "about" simple
app.command(name="about")(about)
