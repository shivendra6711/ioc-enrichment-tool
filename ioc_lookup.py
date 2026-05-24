import requests

API_KEY = "YOUR_VIRUSTOTAL_API_KEY"

headers = {
    "x-apikey": API_KEY
}

ioc = input("Enter IP address or file hash: ")

if "." in ioc and len(ioc.split(".")) == 4:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
else:
    url = f"https://www.virustotal.com/api/v3/files/{ioc}"

response = requests.get(url, headers=headers)

if response.status_code == 200:
    data = response.json()

    stats = data["data"]["attributes"]["last_analysis_stats"]

    print("\n=== VirusTotal Result ===")
    print(f"Malicious : {stats['malicious']}")
    print(f"Suspicious: {stats['suspicious']}")
    print(f"Harmless  : {stats['harmless']}")
    print(f"Undetected: {stats['undetected']}")
else:
    print("Error:", response.status_code)
