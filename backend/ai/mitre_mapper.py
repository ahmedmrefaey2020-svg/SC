"""
MITRE ATT&CK and CVE Mapper
Maps detected attack types to MITRE ATT&CK framework techniques and associated CVE references.
Used to enrich vulnerability scan reports and threat intelligence displays.
"""

from typing import Optional


# MITRE ATT&CK mapping table — keyed by lowercase keywords found in attack type strings
MITRE_MAP = {
    "syn flood": {
        "technique_id": "T1498.001",
        "technique_name": "Network Denial of Service: Direct Network Flood",
        "tactic": "Impact",
        "cves": ["CVE-2018-0296", "CVE-2019-11477"],
        "mitre_url": "https://attack.mitre.org/techniques/T1498/001/",
        "description": "Adversary floods network with SYN packets to exhaust server connection tables.",
    },
    "dos": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "cves": ["CVE-2021-26855", "CVE-2020-10148"],
        "mitre_url": "https://attack.mitre.org/techniques/T1498/",
        "description": "Denial-of-service attack targeting network availability.",
    },
    "ddos": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "cves": ["CVE-2021-44228", "CVE-2022-26143"],
        "mitre_url": "https://attack.mitre.org/techniques/T1498/",
        "description": "Distributed denial-of-service attack using multiple compromised systems.",
    },
    "port scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "cves": ["CVE-2021-22986"],
        "mitre_url": "https://attack.mitre.org/techniques/T1046/",
        "description": "Adversary scans for open ports and running services to identify attack surface.",
    },
    "sql injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "cves": ["CVE-2019-0232", "CVE-2021-44529", "CVE-2022-22963"],
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Attacker injects malicious SQL code into input fields to manipulate database queries.",
    },
    "sqli": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "cves": ["CVE-2019-0232", "CVE-2021-44529"],
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
        "description": "SQL injection attack on a public-facing application.",
    },
    "xss": {
        "technique_id": "T1059.007",
        "technique_name": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution",
        "cves": ["CVE-2021-21985", "CVE-2022-1388"],
        "mitre_url": "https://attack.mitre.org/techniques/T1059/007/",
        "description": "Cross-site scripting injects malicious scripts into web pages viewed by other users.",
    },
    "cross-site scripting": {
        "technique_id": "T1059.007",
        "technique_name": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution",
        "cves": ["CVE-2021-21985"],
        "mitre_url": "https://attack.mitre.org/techniques/T1059/007/",
        "description": "Cross-site scripting attack injecting client-side scripts into web pages.",
    },
    "rce": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "cves": ["CVE-2021-44228", "CVE-2022-22947", "CVE-2021-26084"],
        "mitre_url": "https://attack.mitre.org/techniques/T1059/",
        "description": "Remote code execution allows attackers to run arbitrary code on the target system.",
    },
    "remote code execution": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "cves": ["CVE-2021-44228", "CVE-2022-22947"],
        "mitre_url": "https://attack.mitre.org/techniques/T1059/",
        "description": "Attacker achieves arbitrary code execution on a remote target.",
    },
    "command injection": {
        "technique_id": "T1059.004",
        "technique_name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "Execution",
        "cves": ["CVE-2021-33813", "CVE-2022-42475"],
        "mitre_url": "https://attack.mitre.org/techniques/T1059/004/",
        "description": "Attacker injects OS commands through unsanitized user input.",
    },
    "path traversal": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "cves": ["CVE-2021-41773", "CVE-2021-42013"],
        "mitre_url": "https://attack.mitre.org/techniques/T1083/",
        "description": "Directory traversal exploits insufficient input validation to access files outside root directory.",
    },
    "directory traversal": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "cves": ["CVE-2021-41773", "CVE-2021-42013"],
        "mitre_url": "https://attack.mitre.org/techniques/T1083/",
        "description": "Attacker navigates outside the web root to access sensitive files.",
    },
    "brute force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "cves": ["CVE-2020-28949"],
        "mitre_url": "https://attack.mitre.org/techniques/T1110/",
        "description": "Systematically checking all possible passwords until the correct one is found.",
    },
    "credential stuffing": {
        "technique_id": "T1110.004",
        "technique_name": "Brute Force: Credential Stuffing",
        "tactic": "Credential Access",
        "cves": ["CVE-2021-29441"],
        "mitre_url": "https://attack.mitre.org/techniques/T1110/004/",
        "description": "Using leaked credential lists to attempt unauthorized logins.",
    },
    "privilege escalation": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "cves": ["CVE-2021-4034", "CVE-2022-0847"],
        "mitre_url": "https://attack.mitre.org/techniques/T1068/",
        "description": "Exploiting vulnerabilities to gain elevated system permissions.",
    },
    "lateral movement": {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "cves": ["CVE-2017-0144", "CVE-2021-34527"],
        "mitre_url": "https://attack.mitre.org/techniques/T1021/",
        "description": "Moving through a network to access additional systems after initial compromise.",
    },
    "data exfiltration": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "cves": ["CVE-2021-20323"],
        "mitre_url": "https://attack.mitre.org/techniques/T1041/",
        "description": "Stealing sensitive data and transmitting it to attacker-controlled infrastructure.",
    },
    "exfiltration": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "cves": ["CVE-2021-20323"],
        "mitre_url": "https://attack.mitre.org/techniques/T1041/",
        "description": "Data exfiltration via command-and-control channels.",
    },
    "ransomware": {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "cves": ["CVE-2021-34527", "CVE-2017-0144"],
        "mitre_url": "https://attack.mitre.org/techniques/T1486/",
        "description": "Encrypts victim data and demands payment for decryption key.",
    },
    "phishing": {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
        "cves": ["CVE-2021-40444"],
        "mitre_url": "https://attack.mitre.org/techniques/T1566/",
        "description": "Deceptive communications designed to trick users into revealing sensitive information.",
    },
    "api abuse": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "cves": ["CVE-2022-21449", "CVE-2021-20323"],
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Abusing API endpoints to bypass authentication or extract unauthorized data.",
    },
    "buffer overflow": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "cves": ["CVE-2021-3156", "CVE-2022-0778"],
        "mitre_url": "https://attack.mitre.org/techniques/T1203/",
        "description": "Overwriting memory buffers to corrupt program execution flow.",
    },
    "xxe": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "cves": ["CVE-2021-40438"],
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
        "description": "XML External Entity injection reads sensitive files or performs SSRF via XML parsing.",
    },
    "ssrf": {
        "technique_id": "T1090",
        "technique_name": "Proxy",
        "tactic": "Command and Control",
        "cves": ["CVE-2022-22947", "CVE-2021-26084"],
        "mitre_url": "https://attack.mitre.org/techniques/T1090/",
        "description": "Server-Side Request Forgery forces the server to make requests to internal resources.",
    },
    "idor": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "cves": ["CVE-2021-29441"],
        "mitre_url": "https://attack.mitre.org/techniques/T1078/",
        "description": "Insecure Direct Object Reference bypasses authorization to access other users' objects.",
    },
    "open redirect": {
        "technique_id": "T1566.002",
        "technique_name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "cves": ["CVE-2022-22963"],
        "mitre_url": "https://attack.mitre.org/techniques/T1566/002/",
        "description": "Redirects users to external malicious URLs via unvalidated redirect parameters.",
    },
    "suspicious": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "cves": [],
        "mitre_url": "https://attack.mitre.org/techniques/T1059/",
        "description": "Suspicious activity detected — manual review recommended.",
    },
    "intrusion": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "cves": [],
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Unauthorized access attempt to a networked system.",
    },
}


def get_mitre_mapping(attack_type: str) -> Optional[dict]:
    """
    Deprecated direct lookup kept for reference data only — prefer
    get_mitre_mapping_ai() / enrich_report_with_mitre(), which let the model
    understand the finding's actual context instead of matching keywords.
    Falls back to an exact-key lookup only (no partial keyword scanning).
    """
    if not attack_type:
        return None
    normalized = attack_type.lower().strip()
    return MITRE_MAP.get(normalized)


async def get_mitre_mapping_ai(report_text: str) -> list[dict]:
    """
    Asks the LLM to read the full vulnerability/incident report and decide which
    MITRE ATT&CK categories genuinely apply, based on understanding the actual
    content — not by scanning for keyword substrings. Falls back to an empty
    list (no enrichment) if the LLM is unavailable, rather than guessing.
    """
    if not report_text or not report_text.strip():
        return []

    try:
        import json
        from backend.ai.llm import TOKEN, CANDIDATE_MODELS
        from huggingface_hub import InferenceClient

        if not TOKEN:
            return []

        catalog = "\n".join(f"- {key}: {entry['technique_name']} ({entry['tactic']})" for key, entry in MITRE_MAP.items())
        prompt = (
            "Read the security finding/report below and decide, based on genuine understanding of what "
            "actually happened or was found, which of the following MITRE ATT&CK categories truly apply. "
            "Do not match on keywords alone — only include a category if the underlying technique it "
            "represents is really present in the report.\n\n"
            f"Categories:\n{catalog}\n\n"
            f"Report:\n{report_text[:4000]}\n\n"
            "Respond with ONLY a JSON array of the matching category keys exactly as listed above "
            "(e.g. [\"sql injection\", \"rce\"]). Respond with [] if none genuinely apply. No other text."
        )

        client = InferenceClient(api_key=TOKEN)
        response = client.chat.completions.create(
            model=CANDIDATE_MODELS[0],
            messages=[{"role": "user", "content": prompt}],
            max_tokens=250,
        )
        if not (response and response.choices):
            return []
        raw = (response.choices[0].message.content or "").strip()
        if raw.startswith("```"):
            raw = raw.strip("`")
            if raw.lower().startswith("json"):
                raw = raw[4:]
            raw = raw.strip()
        keys = json.loads(raw)
        return [MITRE_MAP[k] for k in keys if isinstance(k, str) and k in MITRE_MAP]
    except Exception:
        return []


async def enrich_report_with_mitre(report_text: str, context_hint: str = "") -> str:
    """
    Appends a formatted MITRE ATT&CK intelligence block to the end of a scan report.
    The applicable techniques are selected by the LLM reading the actual report content
    (contextual understanding), not by scanning for fixed keyword substrings.

    Args:
        report_text: Original AI-generated vulnerability scan / analysis report.
        context_hint: Optional short label (e.g. filename or scan target) purely for
            logging/context — it is not used for keyword matching.

    Returns:
        Enriched report string with a MITRE block appended for every technique the
        model judged to genuinely apply (may append nothing if none apply or the
        LLM is unavailable).
    """
    mappings = await get_mitre_mapping_ai(report_text)
    if not mappings:
        return report_text

    blocks = []
    for mapping in mappings:
        cve_list = ", ".join(mapping["cves"]) if mapping["cves"] else "No specific CVEs referenced"
        blocks.append(
            f"| Field            | Value                                      |\n"
            f"|------------------|--------------------------------------------|\n"
            f"| Technique ID     | {mapping['technique_id']}                  |\n"
            f"| Technique Name   | {mapping['technique_name']}                |\n"
            f"| Tactic           | {mapping['tactic']}                        |\n"
            f"| CVE References   | {cve_list}                                 |\n"
            f"| Reference URL    | {mapping['mitre_url']}                     |\n\n"
            f"**Description:** {mapping['description']}\n"
        )

    mitre_block = (
        "\n\n---\n\n## MITRE ATT&CK Intelligence Mapping\n\n"
        + "\n---\n\n".join(blocks)
        + "\n\n> These findings were mapped to the MITRE ATT&CK framework by the Sentinel IDS AI "
        "based on the actual content of this report.\n\n---\n"
    )
    return report_text + mitre_block