import json
import subprocess
from typing import List, Dict

def run_safety_check(requirements_file: str) -> List[Dict]:
    """
    Run safety CLI on a requirements.txt file and return a list of vulnerabilities.
    Requires `safety` to be installed (pip install safety).
    """
    try:
        result = subprocess.run(
            ["safety", "check", "--file", requirements_file, "--json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        print("Safety stdout:", result.stdout)  # Debugging line
        print("Safety stderr:", result.stderr)  # Debugging line
        # Extract JSON part from stdout
        json_start = result.stdout.find('{')
        json_end = result.stdout.rfind('}') + 1
        json_content = result.stdout[json_start:json_end]
        
        vulns = json.loads(result.stdout)
        return vulns

    except subprocess.CalledProcessError as e:
        print("❌ Error running safety:", e.stderr)
        return []
    except json.JSONDecodeError as e:
        print("❌ Error decoding JSON:", e)
        print("Safety stdout:", result.stdout)  # Debugging line
        return []