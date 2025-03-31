import os
import pkg_resources
from typing import List, Dict


def parse_requirements(requirements_path: str) -> List[str]:
    """
    Parse a requirements.txt file and return a list of package names.
    """
    if not os.path.exists(requirements_path):
        raise FileNotFoundError(f"{requirements_path} not found.")

    with open(requirements_path, "r") as f:
        lines = f.readlines()

    packages = [
        line.strip().split("==")[0]
        for line in lines
        if line.strip() and not line.startswith("#")
    ]
    return packages


def get_installed_packages() -> List[Dict[str, str]]:
    """
    Returns a list of installed packages with name and version.
    """
    installed = []
    for dist in pkg_resources.working_set:
        installed.append({"name": dist.project_name, "version": dist.version})
    return installed


def match_requirements_with_installed(req_packages: List[str]) -> List[Dict[str, str]]:
    """
    Match required packages with installed ones to get version info.
    """
    installed = get_installed_packages()
    matched = [pkg for pkg in installed if pkg["name"].lower() in [r.lower() for r in req_packages]]
    return matched
