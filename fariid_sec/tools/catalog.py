"""Built-in Kali tool catalog.

Each entry describes a security tool: its binary, category, risk level, and an
install hint shown when the tool is missing. The registry does not assume a
tool is present — every Kali install ships a different subset of the tool
metapackages.
"""

from __future__ import annotations

from dataclasses import dataclass

# Categories
CAT_INFO = "information-gathering"
CAT_WEB = "web"
CAT_VULN = "vulnerability"
CAT_NET = "network"
CAT_WIRELESS = "wireless"
CAT_PASSWORD = "password"  # noqa: S105 (tool category label, not a secret)
CAT_EXPLOIT = "exploitation"
CAT_DNS = "dns"
CAT_SSL = "ssl"
CAT_UTIL = "utility"


@dataclass(frozen=True)
class Tool:
    name: str
    binary: str
    category: str
    risk: str
    description: str
    install_hint: str = ""
    aliases: tuple[str, ...] = ()


def _tool(
    name: str,
    binary: str,
    category: str,
    risk: str,
    description: str,
    install_hint: str = "",
    aliases: tuple[str, ...] = (),
) -> Tool:
    return Tool(name, binary, category, risk, description, install_hint, aliases)


BUILTIN_CATALOG: dict[str, Tool] = {
    # --- information gathering ---
    "nmap": _tool(
        "nmap", "nmap", CAT_NET, "low",
        "Network mapper: port scanning, service/OS detection, NSE scripts.",
        "sudo apt install nmap",
    ),
    "masscan": _tool(
        "masscan", "masscan", CAT_NET, "medium",
        "Very fast TCP port scanner.",
        "sudo apt install masscan",
    ),
    "amass": _tool(
        "amass", "amass", CAT_INFO, "low",
        "In-depth attack surface mapping and subdomain enumeration.",
        "sudo apt install amass",
    ),
    "subfinder": _tool(
        "subfinder", "subfinder", CAT_INFO, "low",
        "Fast passive subdomain discovery.",
        "sudo apt install subfinder",
    ),
    "theharvester": _tool(
        "theHarvester", "theHarvester", CAT_INFO, "low",
        "Email/subdomain gathering from public sources.",
        "sudo apt install theharvester",
        ("theHarvester",),
    ),
    "whois": _tool("whois", "whois", CAT_INFO, "low", "WHOIS domain registration lookup."),
    "dig": _tool("dig", "dig", CAT_DNS, "low", "DNS lookup utility.", "sudo apt install dnsutils"),
    "host": _tool("host", "host", CAT_DNS, "low", "DNS lookup utility.", "sudo apt install dnsutils"),
    "dnsenum": _tool(
        "dnsenum", "dnsenum", CAT_DNS, "low", "DNS enumeration (zone transfer, brute force).",
        "sudo apt install dnsenum",
    ),
    "dnsrecon": _tool(
        "dnsrecon", "dnsrecon", CAT_DNS, "low", "DNS reconnaissance and enumeration.",
        "sudo apt install dnsrecon",
    ),
    # --- web ---
    "nikto": _tool(
        "nikto", "nikto", CAT_WEB, "medium", "Web server scanner for known vulnerabilities.",
        "sudo apt install nikto",
    ),
    "gobuster": _tool(
        "gobuster", "gobuster", CAT_WEB, "low", "Directory/file and DNS brute forcer.",
        "sudo apt install gobuster",
    ),
    "ffuf": _tool(
        "ffuf", "ffuf", CAT_WEB, "medium", "Fast web fuzzer.", "sudo apt install ffuf",
    ),
    "feroxbuster": _tool(
        "feroxbuster", "feroxbuster", CAT_WEB, "medium", "Recursive content discovery.",
        "sudo apt install feroxbuster",
    ),
    "whatweb": _tool(
        "whatweb", "whatweb", CAT_WEB, "low", "Web technology fingerprinting.",
        "sudo apt install whatweb",
    ),
    "httpx": _tool(
        "httpx", "httpx", CAT_WEB, "low", "Fast HTTP probe / web server fingerprinting.",
        "sudo apt install httpx",
    ),
    "curl": _tool("curl", "curl", CAT_WEB, "low", "HTTP client and transfer tool."),
    "wget": _tool("wget", "wget", CAT_WEB, "low", "Non-interactive HTTP downloader."),
    "sqlmap": _tool(
        "sqlmap", "sqlmap", CAT_WEB, "high",
        "Automatic SQL injection detection and exploitation.",
        "sudo apt install sqlmap",
    ),
    # --- vulnerability ---
    "nuclei": _tool(
        "nuclei", "nuclei", CAT_VULN, "medium",
        "Fast template-based vulnerability scanner.",
        "sudo apt install nuclei",
    ),
    "searchsploit": _tool(
        "searchsploit", "searchsploit", CAT_VULN, "low",
        "Local Exploit-DB search.",
        "sudo apt install exploitdb",
    ),
    # --- network ---
    "tcpdump": _tool(
        "tcpdump", "tcpdump", CAT_NET, "medium", "Packet capture (requires root).",
        "sudo apt install tcpdump",
    ),
    "tshark": _tool(
        "tshark", "tshark", CAT_NET, "medium", "Wireshark CLI packet analyzer.",
        "sudo apt install tshark",
    ),
    "netcat": _tool(
        "netcat", "nc", CAT_NET, "medium", "Networking utility (TCP/UDP).",
        "sudo apt install netcat-openbsd",
        ("nc", "netcat"),
    ),
    # --- wireless ---
    "aircrack-ng": _tool(
        "aircrack-ng", "aircrack-ng", CAT_WIRELESS, "high",
        "WEP/WPA key cracking (authorized audits only).",
        "sudo apt install aircrack-ng",
    ),
    "airmon-ng": _tool(
        "airmon-ng", "airmon-ng", CAT_WIRELESS, "high",
        "Enable monitor mode on wireless interfaces.",
        "sudo apt install aircrack-ng",
    ),
    "airodump-ng": _tool(
        "airodump-ng", "airodump-ng", CAT_WIRELESS, "high",
        "Packet capture for wireless networks.",
        "sudo apt install aircrack-ng",
    ),
    # --- password auditing ---
    "john": _tool(
        "john", "john", CAT_PASSWORD, "high", "Password hash cracker.",
        "sudo apt install john",
    ),
    "hashcat": _tool(
        "hashcat", "hashcat", CAT_PASSWORD, "high", "GPU-accelerated password recovery.",
        "sudo apt install hashcat",
    ),
    "hydra": _tool(
        "hydra", "hydra", CAT_PASSWORD, "high", "Online password brute-forcing.",
        "sudo apt install hydra",
    ),
    # --- exploitation / lab ---
    "msfconsole": _tool(
        "metasploit", "msfconsole", CAT_EXPLOIT, "critical",
        "Metasploit Framework console.",
        "sudo apt install metasploit-framework",
        ("msfconsole", "metasploit"),
    ),
    "msfvenom": _tool(
        "msfvenom", "msfvenom", CAT_EXPLOIT, "critical", "Metasploit payload generator.",
        "sudo apt install metasploit-framework",
    ),
    # --- ssl ---
    "openssl": _tool("openssl", "openssl", CAT_SSL, "low", "TLS/certificate inspection and crypto."),
    "sslscan": _tool(
        "sslscan", "sslscan", CAT_SSL, "low", "TLS configuration scanner.", "sudo apt install sslscan",
    ),
    "testssl": _tool(
        "testssl.sh", "testssl.sh", CAT_SSL, "low", "Comprehensive TLS/SSL testing.",
        "sudo apt install testssl.sh",
        ("testssl",),
    ),
}
