from jinja2 import Environment, FileSystemLoader
import os
from typing import List, Dict

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

def generate_html_report(packages: List[Dict], cves: List[Dict], output_path="report.html"):
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("report_template.html")

    html_content = template.render(packages=packages, cves=cves)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"✅ Rapport généré : {output_path}")
