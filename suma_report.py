import requests
import csv
import json
import urllib3

from xmlrpc.client import ServerProxy
import ssl
# Suppress warnings for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Constants
SUMA_URL = "https://suma-server-address.com/rpc/api"
USERNAME = "user"
PASSWORD = "pass"

def post_with_error_handling(method, payload):
    response = getattr(client, method)(*payload)
    try:
        return response
    except requests.HTTPError:
        print(f"HTTP Error {response.status_code}: {response.text}")
        return None
    except json.JSONDecodeError:
        print(f"Failed to decode JSON. Response content: {response.text}")
        return None

# Connect and get session key
context = ssl._create_unverified_context()
client = ServerProxy(SUMA_URL, context=context)

key = post_with_error_handling('auth.login', [USERNAME, PASSWORD])

if not key:
    print("Failed to obtain session key. Exiting.")
    exit()

# Helper function to make further API calls
def call_suma_api(method, *params):
    return post_with_error_handling(method, [key] + list(params))

# Fetch all systems
systems = call_suma_api('system.listSystems')
print(systems)

if not systems:
    print("Failed to fetch systems. Exiting.")
    exit()

report = []

for system in systems:
    print(system["name"])
    system_id = system['id']
    hostname = system['name']

    # Fetch security patches for system
    security_patches = call_suma_api('system.getRelevantErrataByType', system_id, 'Security Advisory')
    if not security_patches:
        print(f"Failed to fetch security patches for system: {hostname}. Skipping.")
        continue

    # Fetch all installed packages
    packages_installed = call_suma_api('system.listPackages', system_id)
    if not packages_installed:
        print(f"Failed to fetch installed packages for system: {hostname}. Skipping.")
        continue

    # Currency percentage calculation
    if len(security_patches) + len(packages_installed) != 0:
        currency_percentage = len(security_patches) / (len(security_patches) + len(packages_installed))
    else:
        currency_percentage = 0

    report.append({
        'Hostname': hostname,
        'Security Patches Available': len(security_patches),
        'Packets Installed': len(packages_installed),
        'Currency Percentage': currency_percentage
    })

# Write the report to a CSV file
with open('suma_report.csv', 'w', newline='') as csvfile:
    fieldnames = ['Hostname', 'Security Patches Available', 'Packets Installed', 'Currency Percentage']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for entry in report:
        writer.writerow(entry)

# Close the session
call_suma_api('auth.logout')
