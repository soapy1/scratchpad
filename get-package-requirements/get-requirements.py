import requests
import sys

package = sys.argv[1]

package = "requests"
url = f"https://pypi.org/pypi/{package}/json"
data = requests.get(url).json()

dependencies = data.get("info", {}).get("requires_dist")
print(dependencies)
