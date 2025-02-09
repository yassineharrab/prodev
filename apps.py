import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# 🔐 Use an environment variable to store the API key securely
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "8b029022280087bb95f40f00ecedf473fce20de4f368b23fbd291b4a57cc4da7")

@app.route("/")
def home():
    return jsonify({"message": "VirusTotal Domain Scanner API is running!"})

@app.route("/scan", methods=["GET"])
def scan_domain():
    domain = request.args.get("domain")

    if not domain:
        return jsonify({"error": "Domain parameter is required"}), 400

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        return jsonify(format_scan_results(data))
    else:
        return jsonify({"error": "Failed to fetch data", "status_code": response.status_code}), response.status_code

def format_scan_results(data):
    """Extract and format scan results from VirusTotal response"""
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    details = attributes.get("last_analysis_results", {})

    results = {
        "domain": data["data"]["id"],
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "safety_rating": "Not Safe" if stats.get("malicious", 0) > 0 else "Safe",
        "creation_date": attributes.get("creation_date"),
        "last_modified": attributes.get("last_modification_date"),
        "whois_country": attributes.get("whois_country"),
        "detailed_analysis": {
            engine: "Malicious" if result["category"] == "malicious" else "Safe"
            for engine, result in details.items()
        },
    }

    return results

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000, debug=True)
