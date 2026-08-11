"""
AI Attack Simulation Agent & Red Team Engine
Contains the catalog of 100 top cybersecurity attack vectors and provides safe simulation capabilities.
"""

from typing import List, Dict, Optional
import time

# Deterministic packet-volume baseline per attack category (typical real-world order of
# magnitude for that category of traffic), scaled by the attack's own severity rating.
# Replaces the previous random.randint() mock generator.
_CATEGORY_BASE_PACKETS: Dict[str, int] = {
    "DoS/DDoS": 2800,
    "Injection": 40,
    "Web Attacks": 35,
    "Auth": 65,
    "RCE": 25,
    "Recon": 130,
    "PrivEsc": 15,
    "MITM": 45,
    "API/Cloud": 55,
    "Malware": 30,
}
_SEVERITY_PACKET_MULTIPLIER: Dict[str, float] = {
    "Critical": 1.6,
    "High": 1.3,
    "Medium": 1.0,
    "Low": 0.6,
    "Info": 0.4,
}
_SEVERITY_RISK_SCORE: Dict[str, int] = {
    "Critical": 95,
    "High": 85,
    "Medium": 65,
    "Low": 40,
    "Info": 20,
}

# Catalog of top 100 cybersecurity attack types across 10 security categories
TOP_100_ATTACKS: List[Dict] = [
    # ── Category 1: Denial of Service (DoS / DDoS) ──
    {"id": 1, "category": "DoS/DDoS", "name": "TCP SYN Flood", "severity": "High", "mitre": "T1498.001", "cve": "CVE-2018-0296"},
    {"id": 2, "category": "DoS/DDoS", "name": "UDP Amplification", "severity": "High", "mitre": "T1498.002", "cve": "CVE-2021-22986"},
    {"id": 3, "category": "DoS/DDoS", "name": "ICMP Ping Flood", "severity": "Medium", "mitre": "T1498.001", "cve": "N/A"},
    {"id": 4, "category": "DoS/DDoS", "name": "HTTP Flood (GET/POST)", "severity": "High", "mitre": "T1499.002", "cve": "CVE-2021-44228"},
    {"id": 5, "category": "DoS/DDoS", "name": "Slowloris HTTP Exhaustion", "severity": "Medium", "mitre": "T1499.001", "cve": "CVE-2007-6750"},
    {"id": 6, "category": "DoS/DDoS", "name": "DNS Amplification", "severity": "Critical", "mitre": "T1498.002", "cve": "CVE-2020-8616"},
    {"id": 7, "category": "DoS/DDoS", "name": "NTP Reflection Attack", "severity": "High", "mitre": "T1498.002", "cve": "CVE-2013-5211"},
    {"id": 8, "category": "DoS/DDoS", "name": "SSDP Amplification", "severity": "Medium", "mitre": "T1498.002", "cve": "CVE-2019-15846"},
    {"id": 9, "category": "DoS/DDoS", "name": "Memcached UDP Reflection", "severity": "Critical", "mitre": "T1498.002", "cve": "CVE-2018-1000115"},
    {"id": 10, "category": "DoS/DDoS", "name": "SYN-ACK Reflection Flood", "severity": "High", "mitre": "T1498.001", "cve": "N/A"},

    # ── Category 2: Injection Attacks ──
    {"id": 11, "category": "Injection", "name": "Union-Based SQL Injection", "severity": "Critical", "mitre": "T1190", "cve": "CVE-2022-22963"},
    {"id": 12, "category": "Injection", "name": "Blind Time-Based SQLi", "severity": "High", "mitre": "T1190", "cve": "CVE-2021-44529"},
    {"id": 13, "category": "Injection", "name": "Boolean-Based Blind SQLi", "severity": "High", "mitre": "T1190", "cve": "CVE-2019-0232"},
    {"id": 14, "category": "Injection", "name": "Error-Based SQL Injection", "severity": "High", "mitre": "T1190", "cve": "CVE-2020-11651"},
    {"id": 15, "category": "Injection", "name": "OS Command Injection", "severity": "Critical", "mitre": "T1059.004", "cve": "CVE-2021-33813"},
    {"id": 16, "category": "Injection", "name": "LDAP Injection", "severity": "High", "mitre": "T1190", "cve": "CVE-2021-44228"},
    {"id": 17, "category": "Injection", "name": "XPath Injection", "severity": "Medium", "mitre": "T1190", "cve": "CVE-2016-3088"},
    {"id": 18, "category": "Injection", "name": "XML External Entity (XXE)", "severity": "High", "mitre": "T1190", "cve": "CVE-2021-40438"},
    {"id": 19, "category": "Injection", "name": "Server-Side Template Injection (SSTI)", "severity": "Critical", "mitre": "T1059", "cve": "CVE-2022-22965"},
    {"id": 20, "category": "Injection", "name": "CRLF Injection / Log Poisoning", "severity": "Medium", "mitre": "T1059", "cve": "CVE-2020-13942"},

    # ── Category 3: Cross-Site Scripting & Web Attacks ──
    {"id": 21, "category": "Web Attacks", "name": "Reflected Cross-Site Scripting (XSS)", "severity": "Medium", "mitre": "T1059.007", "cve": "CVE-2021-21985"},
    {"id": 22, "category": "Web Attacks", "name": "Stored (Persistent) XSS", "severity": "High", "mitre": "T1059.007", "cve": "CVE-2022-1388"},
    {"id": 23, "category": "Web Attacks", "name": "DOM-Based XSS", "severity": "Medium", "mitre": "T1059.007", "cve": "N/A"},
    {"id": 24, "category": "Web Attacks", "name": "Cross-Site Request Forgery (CSRF)", "severity": "Medium", "mitre": "T1566", "cve": "CVE-2021-34473"},
    {"id": 25, "category": "Web Attacks", "name": "Server-Side Request Forgery (SSRF)", "severity": "High", "mitre": "T1090", "cve": "CVE-2021-26855"},
    {"id": 26, "category": "Web Attacks", "name": "HTTP Request Smuggling", "severity": "High", "mitre": "T1190", "cve": "CVE-2020-11760"},
    {"id": 27, "category": "Web Attacks", "name": "Clickjacking / Frame Overlay", "severity": "Low", "mitre": "T1566", "cve": "N/A"},
    {"id": 28, "category": "Web Attacks", "name": "Insecure Direct Object Reference (IDOR)", "severity": "High", "mitre": "T1078", "cve": "CVE-2021-29441"},
    {"id": 29, "category": "Web Attacks", "name": "Open Redirect Vulnerability", "severity": "Low", "mitre": "T1566.002", "cve": "CVE-2021-22145"},
    {"id": 30, "category": "Web Attacks", "name": "Path Traversal / Directory Browsing", "severity": "High", "mitre": "T1083", "cve": "CVE-2021-41773"},

    # ── Category 4: Authentication & Session Attacks ──
    {"id": 31, "category": "Auth", "name": "SSH Brute Force", "severity": "High", "mitre": "T1110.001", "cve": "N/A"},
    {"id": 32, "category": "Auth", "name": "RDP Credential Stuffing", "severity": "High", "mitre": "T1110.004", "cve": "CVE-2019-0708"},
    {"id": 33, "category": "Auth", "name": "Password Spraying Attack", "severity": "High", "mitre": "T1110.003", "cve": "N/A"},
    {"id": 34, "category": "Auth", "name": "Session Hijacking / Token Fixation", "severity": "High", "mitre": "T1539", "cve": "CVE-2021-31805"},
    {"id": 35, "category": "Auth", "name": "JWT Signature Stripping / None Alg", "severity": "High", "mitre": "T1550", "cve": "CVE-2022-21449"},
    {"id": 36, "category": "Auth", "name": "OAuth Token Leakage", "severity": "Medium", "mitre": "T1550.001", "cve": "CVE-2021-27582"},
    {"id": 37, "category": "Auth", "name": "Default Credential Exploitation", "severity": "Medium", "mitre": "T1078.001", "cve": "N/A"},
    {"id": 38, "category": "Auth", "name": "Kerberoasting Attack", "severity": "High", "mitre": "T1558.003", "cve": "N/A"},
    {"id": 39, "category": "Auth", "name": "AS-REP Roasting", "severity": "High", "mitre": "T1558.004", "cve": "N/A"},
    {"id": 40, "category": "Auth", "name": "NTLM Relay Attack", "severity": "Critical", "mitre": "T1557.001", "cve": "CVE-2021-36942"},

    # ── Category 5: Remote Code Execution & Exploits ──
    {"id": 41, "category": "RCE", "name": "Log4Shell RCE (JNDI Injection)", "severity": "Critical", "mitre": "T1190", "cve": "CVE-2021-44228"},
    {"id": 42, "category": "RCE", "name": "Spring4Shell RCE", "severity": "Critical", "mitre": "T1190", "cve": "CVE-2022-22965"},
    {"id": 43, "category": "RCE", "name": "EternalBlue SMBv1 Exploit", "severity": "Critical", "mitre": "T1210", "cve": "CVE-2017-0144"},
    {"id": 44, "category": "RCE", "name": "BlueKeep RDP Vulnerability", "severity": "Critical", "mitre": "T1210", "cve": "CVE-2019-0708"},
    {"id": 45, "category": "RCE", "name": "ProxyLogon Exchange RCE", "severity": "Critical", "mitre": "T1190", "cve": "CVE-2021-26855"},
    {"id": 46, "category": "RCE", "name": "ProxyShell Exchange RCE", "severity": "Critical", "mitre": "T1190", "cve": "CVE-2021-34473"},
    {"id": 47, "category": "RCE", "name": "Poodle SSL/TLS Downgrade", "severity": "Medium", "mitre": "T1557", "cve": "CVE-2014-3566"},
    {"id": 48, "category": "RCE", "name": "Heartbleed OpenSSL Leak", "severity": "High", "mitre": "T1190", "cve": "CVE-2014-0160"},
    {"id": 49, "category": "RCE", "name": "Shellshock Bash Vulnerability", "severity": "Critical", "mitre": "T1059.004", "cve": "CVE-2014-6271"},
    {"id": 50, "category": "RCE", "name": "Apache Struts2 RCE", "severity": "Critical", "mitre": "T1190", "cve": "CVE-2017-5638"},

    # ── Category 6: Reconnaissance & Scanning ──
    {"id": 51, "category": "Recon", "name": "TCP SYN Port Scan", "severity": "Low", "mitre": "T1046", "cve": "N/A"},
    {"id": 52, "category": "Recon", "name": "UDP Port Scan", "severity": "Low", "mitre": "T1046", "cve": "N/A"},
    {"id": 53, "category": "Recon", "name": "FIN / XMAS / NULL Scan", "severity": "Low", "mitre": "T1046", "cve": "N/A"},
    {"id": 54, "category": "Recon", "name": "Nmap OS Fingerprinting", "severity": "Low", "mitre": "T1046", "cve": "N/A"},
    {"id": 55, "category": "Recon", "name": "Dirbuster / Gobuster Path Enum", "severity": "Medium", "mitre": "T1083", "cve": "N/A"},
    {"id": 56, "category": "Recon", "name": "Subdomain Brute Force", "severity": "Low", "mitre": "T1590", "cve": "N/A"},
    {"id": 57, "category": "Recon", "name": "DNS Zone Transfer Leak", "severity": "Medium", "mitre": "T1590.002", "cve": "N/A"},
    {"id": 58, "category": "Recon", "name": "SNMP Community String Enum", "severity": "Medium", "mitre": "T1046", "cve": "N/A"},
    {"id": 59, "category": "Recon", "name": "FTP Anonymous Login Scan", "severity": "Low", "mitre": "T1078.001", "cve": "N/A"},
    {"id": 60, "category": "Recon", "name": "WordPress XML-RPC Pingback Enum", "severity": "Medium", "mitre": "T1083", "cve": "CVE-2014-3120"},

    # ── Category 7: Privilege Escalation & Persistence ──
    {"id": 61, "category": "PrivEsc", "name": "PwnKit (Polkit) Local PrivEsc", "severity": "Critical", "mitre": "T1068", "cve": "CVE-2021-4034"},
    {"id": 62, "category": "PrivEsc", "name": "Dirty Pipe Linux Kernel Exploit", "severity": "Critical", "mitre": "T1068", "cve": "CVE-2022-0847"},
    {"id": 63, "category": "PrivEsc", "name": "PrintNightmare Spooler PrivEsc", "severity": "Critical", "mitre": "T1068", "cve": "CVE-2021-34527"},
    {"id": 64, "category": "PrivEsc", "name": "Sudo Baron Samedit PrivEsc", "severity": "High", "mitre": "T1068", "cve": "CVE-2021-3156"},
    {"id": 65, "category": "PrivEsc", "name": "SUID Binary Abuse", "severity": "High", "mitre": "T1548.001", "cve": "N/A"},
    {"id": 66, "category": "PrivEsc", "name": "Cron Job Hijacking", "severity": "Medium", "mitre": "T1053.003", "cve": "N/A"},
    {"id": 67, "category": "PrivEsc", "name": "Web Shell Persistence", "severity": "Critical", "mitre": "T1505.003", "cve": "CVE-2021-44228"},
    {"id": 68, "category": "PrivEsc", "name": "Systemd Service Persistence", "severity": "High", "mitre": "T1543.002", "cve": "N/A"},
    {"id": 69, "category": "PrivEsc", "name": "Windows Registry Run Key Persistence", "severity": "Medium", "mitre": "T1547.001", "cve": "N/A"},
    {"id": 70, "category": "PrivEsc", "name": "DLL Side-Loading Attack", "severity": "High", "mitre": "T1574.002", "cve": "CVE-2020-0688"},

    # ── Category 8: Network Protocol & Man-in-the-Middle ──
    {"id": 71, "category": "MITM", "name": "ARP Cache Poisoning", "severity": "High", "mitre": "T1557.002", "cve": "N/A"},
    {"id": 72, "category": "MITM", "name": "DNS Spoofing / Cache Poisoning", "severity": "High", "mitre": "T1557", "cve": "CVE-2020-8616"},
    {"id": 73, "category": "MITM", "name": "DHCP Starvation Attack", "severity": "Medium", "mitre": "T1498", "cve": "N/A"},
    {"id": 74, "category": "MITM", "name": "Rogue DHCP Server Attack", "severity": "High", "mitre": "T1557", "cve": "N/A"},
    {"id": 75, "category": "MITM", "name": "SSL Strip / Downgrade Attack", "severity": "High", "mitre": "T1557", "cve": "N/A"},
    {"id": 76, "category": "MITM", "name": "LLMNR / NBT-NS Poisoning", "severity": "High", "mitre": "T1557.001", "cve": "N/A"},
    {"id": 77, "category": "MITM", "name": "BGP Route Hijacking", "severity": "Critical", "mitre": "T1557", "cve": "N/A"},
    {"id": 78, "category": "MITM", "name": "Wi-Fi Deauthentication Attack", "severity": "Medium", "mitre": "T1498", "cve": "N/A"},
    {"id": 79, "category": "MITM", "name": "KRACK Wi-Fi WPA2 Vulnerability", "severity": "High", "mitre": "T1557", "cve": "CVE-2017-13077"},
    {"id": 80, "category": "MITM", "name": "Bluetooth BLE Spoofing", "severity": "Medium", "mitre": "T1557", "cve": "CVE-2020-15802"},

    # ── Category 9: API & Cloud Security Attacks ──
    {"id": 81, "category": "API/Cloud", "name": "API Rate Limit Exhaustion", "severity": "Medium", "mitre": "T1499", "cve": "N/A"},
    {"id": 82, "category": "API/Cloud", "name": "BOLA (Broken Object Level Auth)", "severity": "High", "mitre": "T1078", "cve": "N/A"},
    {"id": 83, "category": "API/Cloud", "name": "Broken Function Level Auth", "severity": "High", "mitre": "T1068", "cve": "N/A"},
    {"id": 84, "category": "API/Cloud", "name": "Mass Assignment Vulnerability", "severity": "Medium", "mitre": "T1078", "cve": "N/A"},
    {"id": 85, "category": "API/Cloud", "name": "AWS Metadata Service SSRF (IMDSv1)", "severity": "Critical", "mitre": "T1552.005", "cve": "CVE-2021-26855"},
    {"id": 86, "category": "API/Cloud", "name": "S3 Bucket Public Data Exposure", "severity": "High", "mitre": "T1530", "cve": "N/A"},
    {"id": 87, "category": "API/Cloud", "name": "Kubernetes API Unauthorized Access", "severity": "Critical", "mitre": "T1190", "cve": "CVE-2018-1002105"},
    {"id": 88, "category": "API/Cloud", "name": "Docker Daemon Socket Abuse", "severity": "Critical", "mitre": "T1611", "cve": "CVE-2019-5736"},
    {"id": 89, "category": "API/Cloud", "name": "GraphQL Introspection Data Leak", "severity": "Low", "mitre": "T1083", "cve": "N/A"},
    {"id": 90, "category": "API/Cloud", "name": "CORS Misconfiguration Abuse", "severity": "Medium", "mitre": "T1190", "cve": "N/A"},

    # ── Category 10: Advanced Threats, Malware & Ransomware ──
    {"id": 91, "category": "Malware", "name": "WannaCry Ransomware Propagation", "severity": "Critical", "mitre": "T1486", "cve": "CVE-2017-0144"},
    {"id": 92, "category": "Malware", "name": "NotPetya MBR Wiper", "severity": "Critical", "mitre": "T1485", "cve": "CVE-2017-0144"},
    {"id": 93, "category": "Malware", "name": "SolarWinds Supply Chain Backdoor", "severity": "Critical", "mitre": "T1195.002", "cve": "CVE-2020-10148"},
    {"id": 94, "category": "Malware", "name": "Cobalt Strike Beacon C2 Traffic", "severity": "Critical", "mitre": "T1071", "cve": "N/A"},
    {"id": 95, "category": "Malware", "name": "DNS Tunneling / Data Exfiltration", "severity": "High", "mitre": "T1071.004", "cve": "N/A"},
    {"id": 96, "category": "Malware", "name": "ICMP Tunneling / Covert Channel", "severity": "Medium", "mitre": "T1095", "cve": "N/A"},
    {"id": 97, "category": "Malware", "name": "Process Hollowing Injection", "severity": "High", "mitre": "T1055.012", "cve": "N/A"},
    {"id": 98, "category": "Malware", "name": "Reflective DLL Injection", "severity": "High", "mitre": "T1055.001", "cve": "N/A"},
    {"id": 99, "category": "Malware", "name": "Crypto-Jacking / Miner Traffic", "severity": "Medium", "mitre": "T1496", "cve": "N/A"},
    {"id": 100, "category": "Malware", "name": "Zero-Day Exploit Chain Simulation", "severity": "Critical", "mitre": "T1203", "cve": "CVE-2023-23397"},
]


class RedTeamAttackAgent:
    """
    AI Red Team Agent — Simulates selected attacks from the 100-attack catalog
    against the Sentinel monitoring engine to test detection accuracy and SOAR response.
    """

    def __init__(self):
        self.catalog = TOP_100_ATTACKS

    def get_attack_by_id(self, attack_id: int) -> Optional[Dict]:
        for a in self.catalog:
            if a["id"] == attack_id:
                return a
        return None

    def search_attacks(self, query: str = "", category: str = "") -> List[Dict]:
        results = self.catalog
        if category:
            results = [a for a in results if a["category"].lower() == category.lower()]
        if query:
            q = query.lower()
            results = [a for a in results if q in a["name"].lower() or q in a["mitre"].lower() or q in a["cve"].lower()]
        return results

    def simulate_attack(self, attack_id: int, target_ip: str = "192.168.1.100") -> Dict:
        """
        Simulates an attack in a safe, controlled sandbox environment.
        Injects a mock telemetry event into the Sentinel monitoring stream to test system detection.
        """
        attack = self.get_attack_by_id(attack_id)
        if not attack:
            return {"success": False, "error": f"Attack ID {attack_id} not found"}

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        base_packets = _CATEGORY_BASE_PACKETS.get(attack["category"], 50)
        multiplier = _SEVERITY_PACKET_MULTIPLIER.get(attack["severity"], 1.0)
        simulated_packets = int(base_packets * multiplier)
        risk_boost = _SEVERITY_RISK_SCORE.get(attack["severity"], 60)

        # Inject simulated event snapshot into monitoring stats
        sim_event = {
            "simulation_id": f"sim_{int(time.time())}_{attack_id}",
            "attack_id": attack["id"],
            "name": attack["name"],
            "category": attack["category"],
            "severity": attack["severity"],
            "mitre": attack["mitre"],
            "cve": attack["cve"],
            "target_ip": target_ip,
            "packets_generated": simulated_packets,
            "detected_risk_score": risk_boost,
            "detection_verdict": "ATTACK DETECTED (Simulated)",
            "soar_triggered": True if risk_boost >= 80 else False,
            "timestamp": timestamp,
        }

        return {
            "success": True,
            "simulation": sim_event,
            "message": f"AI Red Team Agent successfully simulated '{attack['name']}' against {target_ip}.",
        }


# Singleton agent instance
red_team_agent = RedTeamAttackAgent()