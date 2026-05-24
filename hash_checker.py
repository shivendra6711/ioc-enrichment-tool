import requests

API_KEY = "YOUR_VIRUSTOTAL_API_KEY"

headers = {
    "x-apikey": API_KEY
}

file_hash = input("Enter file hash: ")

url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

response = requests.get(url, headers=headers)

if response.status_code == 200:
    data = response.json()

    stats = data["data"]["attributes"]["last_analysis_stats"]

    print("\n=== Hash Reputation ===")
    print(f"Malicious : {stats['malicious']}")
    print(f"Suspicious: {stats['suspicious']}")
    print(f"Harmless  : {stats['harmless']}")
else:
    print("Lookup failed")
