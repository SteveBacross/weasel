from pathlib import Path
from datetime import datetime
import json
import logging
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML


def build_report_data(dependencies, vulnerabilities, licenses, bandit_issues):
    return {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "dependencies": dependencies,
        "vulnerabilities": vulnerabilities,
        "licenses": licenses,
        "bandit": bandit_issues,
    }

def generate_reports(report_data: dict, output_dir: Path, formats: list):
    output_dir.mkdir(parents=True, exist_ok=True)
    env = Environment(loader=FileSystemLoader("weasel/report/templates"))
    template = env.get_template("report_template.html")

    html_content = template.render(report=report_data)

    if "html" in formats:
        html_path = output_dir / "report.html"
        html_path.write_text(html_content, encoding="utf-8")
        logging.info(f"Rapport HTML généré : {html_path}")

    if "pdf" in formats:
        pdf_path = output_dir / "report.pdf"
        HTML(string=html_content).write_pdf(str(pdf_path))
        logging.info(f"Rapport PDF généré : {pdf_path}")

    if "json" in formats:
        json_path = output_dir / "report.json"
        with json_path.open("w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        logging.info(f"Rapport JSON généré : {json_path}")
