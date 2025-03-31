import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from module_inspector import scanner, cve_checker, license_checker, report_generator

def main():
    req_file = "requirements.txt"
    print(f"📦 Scanning requirements from {req_file}...\n")
    reqs = scanner.parse_requirements(req_file)
    matched = scanner.match_requirements_with_installed(reqs)

    print("🔍 Packages found:")
    for pkg in matched:
        print(f"- {pkg['name']} ({pkg['version']})")
        
    print("\n🛡️ Checking for CVEs with Safety...\n")
    vulnerabilities = cve_checker.run_safety_check(req_file)

    if vulnerabilities:
        for vuln in vulnerabilities:
            print(f"- {vuln['package_name']} {vuln['affected_versions']} ⚠️")
            print(f"  > CVE: {vuln.get('cve')}, {vuln['description']}")
    else:
        print("✅ Aucun CVE trouvé !")
        
    print("\n📄 Scanning licenses...\n")
    licenses = license_checker.get_licenses_for_packages(matched)

    for entry in licenses:
        print(f"- {entry['name']} ({entry['version']}): {entry['license']}")
        
        report_generator.generate_html_report(
        packages=licenses,
        cves=vulnerabilities,
        output_path="module_inspector_report.html"
    )
    #graph_builder.generate_dependency_graph(output_path="dependency_graph.html")


if __name__ == "__main__":
    main()
