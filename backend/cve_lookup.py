import os
import requests

# Lightweight mapping from common attack names to a canonical CVE + risk metadata.
# This provides immediate, high-quality output for known terms even if the NVD API
# is unreachable or rate-limited.
ATTACK_LOOKUP = {
    "log4j": {
        "id": "CVE-2021-44228",
        "severity": "Critical",
        "risk_score": "10.0",
        "threat": "Remote Code Execution (RCE)",
        "description": "Apache Log4j2 remote code execution vulnerability (Log4Shell).",
        "vulnerability": "CWE-502",
        "impact": "Full system compromise, data theft, malware injection",
        "mitigation": "Update Log4j to the latest version and disable JNDI lookups.",
    },
    "log4shell": {
        "id": "CVE-2021-44228",
        "severity": "Critical",
        "risk_score": "10.0",
        "threat": "Remote Code Execution (RCE)",
        "description": "Apache Log4j2 remote code execution vulnerability (Log4Shell).",
        "vulnerability": "CWE-502",
        "impact": "Full system compromise, data theft, malware injection",
        "mitigation": "Update Log4j to the latest version and disable JNDI lookups.",
    },
    "sql injection": {
        "id": "CWE-89",
        "severity": "High",
        "risk_score": "9.0",
        "threat": "Database compromise",
        "description": "Injection of malicious SQL queries to access or modify a database.",
        "mitigation": "Use prepared statements, parameterized queries, and input validation.",
    },
    "xss": {
        "id": "CWE-79",
        "severity": "High",
        "risk_score": "8.2",
        "threat": "Client-side script execution",
        "description": "Malicious scripts injected into web pages viewed by other users.",
        "mitigation": "Use output encoding, input sanitization, and Content Security Policy (CSP).",
    },
    "csrf": {
        "id": "CWE-352",
        "severity": "Medium",
        "risk_score": "6.5",
        "threat": "Unauthorized actions",
        "description": "Forces authenticated users to perform unwanted actions.",
        "mitigation": "Implement CSRF tokens and same-site cookies.",
    },
    "ddos": {
        "id": "N/A",
        "severity": "High",
        "risk_score": "8.5",
        "threat": "Service disruption",
        "description": "Overwhelms systems with traffic to cause service outages.",
        "mitigation": "Use rate limiting, traffic filtering, and DDoS protection services.",
    },
    "ransomware": {
        "id": "Multiple",
        "severity": "Critical",
        "risk_score": "9.5",
        "threat": "Data encryption and extortion",
        "description": "Encrypts files and demands ransom to restore access.",
        "mitigation": "Maintain offline backups, patch systems, and use endpoint protection.",
    },
    "phishing": {
        "id": "N/A",
        "severity": "High",
        "risk_score": "7.5",
        "threat": "Credential theft",
        "description": "Fake emails or sites trick users into revealing sensitive data.",
        "mitigation": "Train users, use email filtering, and enable MFA.",
    },
}


def fetch_cve(keyword):
    """Return a dict with results and an optional error message from the NVD API."""

    normalized = (keyword or "").strip().lower()
    if normalized in ATTACK_LOOKUP:
        return {"results": [ATTACK_LOOKUP[normalized]], "error": None}

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keyword": keyword}

    # Optionally allow the user to supply an NVD API key via environment vars.
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        params["apiKey"] = api_key

    headers = {"User-Agent": "AI-Security-Copilot/1.0"}

    try:
        response = requests.get(base_url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        # If the request fails, return an error message rather than crashing.
        return {"results": [], "error": str(e)}

    results = []
    for item in data.get("vulnerabilities", [])[:5]:  # top 5 results
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc and cve.get("descriptions"):
            desc = cve.get("descriptions")[0].get("value", "")

        threat = ""
        vulnerability = ""
        risk_score = ""

        # Extract CVSS v3.1 data for threat and risk score
        if cve.get("metrics") and cve["metrics"].get("cvssMetricV31"):
            metric = cve["metrics"]["cvssMetricV31"][0]
            cvss = metric.get("cvssData", {})
            risk_score = str(cvss.get("baseScore", ""))
            attack_vector = cvss.get("attackVector", "")
            severity = cvss.get("baseSeverity", "")
            threat = f"{attack_vector} ({severity})" if attack_vector and severity else ""

        # Extract CWE for vulnerability
        if cve.get("weaknesses"):
            for w in cve["weaknesses"]:
                for d in w.get("description", []):
                    if d.get("lang") == "en":
                        vulnerability = d.get("value", "")
                        break
                if vulnerability:
                    break

        if cve_id:
            results.append({"id": cve_id, "description": desc, "threat": threat, "vulnerability": vulnerability, "risk_score": risk_score})

    return {"results": results, "error": None}
