import typer
from pathlib import Path
from typing import List
from weasel.parser.requirements import parse_requirements, resolve_all_dependencies
from weasel.scanner.cve_scanner import get_cve_for_package, format_cve
from weasel.scanner.license_checker import get_licenses, simplify_license_info
from weasel.code_analysis.code_checker import run_bandit_scan
from weasel.graph.dependency_graph import generate_dependency_graph
from weasel.report.report_generator import build_report_data, generate_reports

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
    typer.echo("\n🚀 Démarrage de l'analyse avec Weasel...")
    typer.echo(f"📄 Fichier requirements: {requirements}")

    parsed_packages = parse_requirements(requirements)
    typer.echo(f"🔍 {len(parsed_packages)} dépendance(s) directes trouvées")
    for pkg in parsed_packages:
        typer.echo(f"  - {pkg['name']} {pkg['specifier']}")

    resolved_packages = resolve_all_dependencies(requirements)
    all_vulns = {}
    license_infos = []
    bandit_results = []

    if cve:
        typer.echo("\n🛡️ Analyse des CVEs...")
        for pkg in resolved_packages:
            name = pkg.get("name")
            version = pkg.get("version")
            if not version:
                typer.echo(f"[WARN] {name} sans version, CVE ignoré.")
                continue
            vulns = get_cve_for_package(name, version, offline=offline)
            if vulns:
                all_vulns[name] = [format_cve(v) for v in vulns]
                typer.echo(f"🚨 Vulnérabilités pour {name}=={version} : {len(vulns)}")
            else:
                typer.echo(f"✅ {name}=={version} : aucune vulnérabilité")

    if licenses:
        typer.echo("\n📜 Analyse des licences...")
        raw = get_licenses(offline=offline)
        license_infos = simplify_license_info(raw)
        for lic in license_infos:
            typer.echo(f"  - {lic['name']}: {lic['license']} ({lic['permissivity']})")

    if code_check:
        typer.echo("\n🔎 Analyse du code source (Bandit)...")
        bandit_results = run_bandit_scan(".", severity_level=severity_level, ignored_tests=ignore_rules)
        for issue in bandit_results:
            typer.echo(f"🚨 {issue['filename']}:{issue['line_number']} - {issue['test_id']} {issue['issue_text']}")

    if graph:
        typer.echo("\n📊 Génération du graphe...")
        vuln_names = list(all_vulns.keys())
        graph_path = output / "dependencies.html"
        generate_dependency_graph(resolved_packages, vuln_names, str(graph_path))
        typer.echo(f"✅ Graphe généré : {graph_path}")

    if any([cve, licenses, code_check]):
        typer.echo("\n📝 Génération du rapport...")
        report_data = build_report_data(resolved_packages, all_vulns, license_infos, bandit_results)
        generate_reports(report_data, output, formats=report_format)
        typer.echo(f"📁 Rapport disponible dans : {output}")
