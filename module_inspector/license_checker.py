import importlib.metadata
from typing import List, Dict


def get_package_license(package_name: str) -> str:
    """
    Get the license for a given package using importlib.metadata.
    Returns 'Unknown' if not found.
    """
    try:
        metadata = importlib.metadata.metadata(package_name)
        license_str = metadata.get("License")
        if license_str and license_str.strip():
            return license_str.strip()
        
        # Fallback : check classifiers
        classifiers = metadata.get_all("Classifier") or []
        for classifier in classifiers:
            if classifier.startswith("License"):
                return classifier.split("::")[-1].strip()

        return "Unknown"
    except importlib.metadata.PackageNotFoundError:
        return "Not installed"
    except Exception as e:
        return f"Error: {str(e)}"


def get_licenses_for_packages(packages: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    Add license info to each package (expects list of dicts with name + version).
    """
    results = []
    for pkg in packages:
        license_type = get_package_license(pkg["name"])
        results.append({
            "name": pkg["name"],
            "version": pkg["version"],
            "license": license_type
        })
    return results
