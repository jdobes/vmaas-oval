import json
import sys

import requests

LOCAL_URL = "http://localhost:8000/vulnerabilities"
VMAAS_URL = "https://console.redhat.com/api/vmaas/v3/vulnerabilities"


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} path/to/system/profile.json")
        sys.exit(1)

    with open(sys.argv[1], "rt") as sys_profile_file:
        sys_profile = json.load(sys_profile_file)

    # Get CVEs from local instance
    response = requests.post(LOCAL_URL,
                             json=sys_profile)
    local_cves = sorted(response.json()["cve_list"])
    local_unpatched_cves = sorted(response.json()["unpatched_cve_list"])

    # Get CVEs from public VMaaS instance
    response = requests.post(VMAAS_URL,
                             json=sys_profile,
                             headers={"Content-type": "application/json"})
    vmaas_cves = sorted(response.json()["cve_list"])

    print(f"Number of CVEs returned from localhost: {len(local_cves)}")
    print(f"Number of CVEs returned from VMaaS: {len(vmaas_cves)}")
    print(f"Number of CVEs without a patch returned from localhost: {len(local_unpatched_cves)}")
    print(f"CVEs returned from localhost but not from VMaaS: {[cve for cve in local_cves if cve not in vmaas_cves]}")
    print(f"CVEs returned from VMaaS but not from localhost: {[cve for cve in vmaas_cves if cve not in local_cves]}")

if __name__ == "__main__":
    main()
