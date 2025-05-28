import os
import typer
from pathlib import Path
from typing import List
import yaml
from weasel.parser.requirements import parse_requirements, resolve_all_dependencies, get_package_author, compute_full_origins
from weasel.scanner.cve_scanner import get_cve_for_package,get_cves_for_packages, format_cve
from weasel.scanner.license_checker import get_licenses, simplify_license_info
from weasel.code_analysis.code_checker import run_bandit_scan
from weasel.graph.dependency_graph import generate_dependency_graph
from weasel.graph.generate_dependency_graph_dash import generate_dependency_graph_dash
from weasel.report.report_generator import build_report_data, generate_reports

def load_config(config_path: Path) -> dict:
    if config_path and config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {}

def run_scan(
    requirements: Path = typer.Option(..., "--requirements", "-r", exists=True),
    cve: bool = typer.Option(False),
    licenses: bool = typer.Option(False),
    graph: bool = typer.Option(False),
    code_check: bool = typer.Option(False),
    severity_level: str = typer.Option("low"),
    ignore_rules: List[str] = typer.Option([]),
    report_format: List[str] = typer.Option(["html"]),
    output: Path = typer.Option(Path("weasel_report")),
    offline: bool = typer.Option(False),
    config: Path = typer.Option(None)
):
    """
    Exécute l'analyse complète de sécurité.
    """
    typer.echo("Démarrage de l'analyse avec Weasel...")
    typer.echo(f"Fichier requirements: {requirements}")

    parsed_packages = parse_requirements(requirements)
    typer.echo(f"🔍 {len(parsed_packages)} dépendance(s) directes trouvées")
    for pkg in parsed_packages:
        typer.echo(f"  - {pkg['name']} {pkg['specifier']}")

    resolved_packages = resolve_all_dependencies(requirements)
    # récupère tous les chemins de dépendance
    origins_map = compute_full_origins(requirements)
    
    print(origins_map)
    for pkg in resolved_packages:
        name = pkg["name"]
        pkg["author"] = get_package_author(name)
        pkg["origin"] = origins_map.get(name, "direct")
    
    all_vulns = {}
    license_infos = []
    bandit_results = []

    typer.echo(f"[DEBUG] Répertoire courant : {os.getcwd()}")
    # Charger la configuration YAML si fournie
    config_data = load_config(config) if config else {}
    bandit_config = config_data.get("bandit", {})
    excluded_dirs = bandit_config.get("excluded_dirs", [])
    ignore_tests = bandit_config.get("ignore_tests", ignore_rules)

    if cve:
        typer.echo("Analyse des CVEs en batch…")
        # Prépare la liste name/version pour lesquels on a une version
        pkg_list = [
            {"name": pkg["name"], "version": pkg["version"]}
            for pkg in resolved_packages
            if pkg.get("version")
        ]
        # Requête batch et récupération du mapping name -> list[vuln]
        batch_map = get_cves_for_packages(pkg_list, offline=offline)

        for name, vulns in batch_map.items():
            if vulns:
                all_vulns[name] = [format_cve(v) for v in vulns]
                typer.echo(f"• {name}: {len(vulns)} vulnérabilités détectées")
            else:
                typer.echo(f"• {name}: aucune vulnérabilité")

    if licenses:
        typer.echo("Analyse des licences...")
        raw = get_licenses(offline=offline)
        license_infos = simplify_license_info(raw)
        for lic in license_infos:
            typer.echo(f"  - {lic['name']}: {lic['license']} ({lic['permissivity']})")

    if code_check:
        typer.echo("Analyse du code source")
        bandit_results = run_bandit_scan("weasel", severity_level=severity_level, ignored_tests=ignore_tests, exclude_dirs=excluded_dirs)
        for issue in bandit_results:
            typer.echo(f"{issue['filename']}:{issue['line_number']} - {issue['test_id']} {issue['issue_text']}")

    if graph:
       typer.echo("Génération du graphe interactif Dash/Cytoscape…")
       # Chemin de sortie
       dash_path = output / "dependencies_dash.html"
       # Liste des paquets directement déclarés
       direct_names = [pkg["name"] for pkg in parsed_packages]
       # Appel avec resolved_packages, direct_packages et map des vulnérabilités
       generate_dependency_graph_dash(
            dash_path,
            resolved_packages,
            direct_names,
            all_vulns
        )
    typer.echo(f"Graphe interactif généré : {dash_path}")

    if any([cve, licenses, code_check]):
        typer.echo("Génération du rapport...")
        report_data = build_report_data(resolved_packages, all_vulns, license_infos, bandit_results)
        print("--------------------------------------------------------------------------------------------")
        print(resolved_packages[:3])
        print("--------------------------------------------------------------------------------------------")
        generate_reports(report_data, output, formats=report_format)
        typer.echo(f"Rapport disponible dans : {output}")
