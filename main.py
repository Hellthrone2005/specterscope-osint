import re
import os
import sys
import webbrowser
import requests
from colorama import Fore, Style, init
from dotenv import load_dotenv

# Initialize color processing for Windows 11 terminal
init(autoreset=True)

# Load environment variables from local secure .env file
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

# Force-strip hidden formatting spaces or line breaks from the loaded keys
if VT_API_KEY: VT_API_KEY = str(VT_API_KEY).strip()
if ABUSE_API_KEY: ABUSE_API_KEY = str(ABUSE_API_KEY).strip()
if OTX_API_KEY: OTX_API_KEY = str(OTX_API_KEY).strip()


def detect_ioc_type(ioc):
    """Inspects string format via regex patterns to route asset types."""
    ip_pattern = r"^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    md5_pattern = r"^[a-fA-F0-9]{32}$"
    sha256_pattern = r"^[a-fA-F0-9]{64}$"

    if re.match(ip_pattern, ioc): 
        return "IP"
    elif re.match(md5_pattern, ioc) or re.match(sha256_pattern, ioc): 
        return "HASH"
    return None

# =========================================================================
# LIVE API CONNECTOR MODULES WITH RESILIENCY HANDLING
# =========================================================================

def fetch_virustotal(ioc, ioc_type):
    if not VT_API_KEY:
        return {"malicious": "Missing Key", "suspicious": 0, "harmless": 0}
        
    headers = {"x-apikey": VT_API_KEY}
    endpoint_type = "ip_addresses" if ioc_type == "IP" else "files"
    url = f"https://www.virustotal.com/api/v3/{endpoint_type}/{ioc}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)
            }
        elif response.status_code == 429:
            print(Fore.YELLOW + "[!] VirusTotal Warning: Rate-limit hit (4 Lookups/min limit).")
            return {"malicious": "Rate Limited", "suspicious": "Rate Limited", "harmless": "Wait 60s"}
        elif response.status_code == 404:
            return {"malicious": 0, "suspicious": 0, "harmless": "Clean / Unseen"}
    except Exception as e:
        print(Fore.RED + f"[-] VirusTotal Query Error: {e}")
    return None

def fetch_abuseipdb(ioc):
    if not ABUSE_API_KEY:
        return {"score": 0, "total_reports": "Missing Key", "isp": "N/A", "country": "N/A"}
        
    headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ioc, "maxAgeInDays": "90"}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()['data']
            return {
                "score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "isp": data.get("isp", "Unknown"),
                "country": data.get("countryCode", "Unknown")
            }
        elif response.status_code == 429:
            return {"score": "Limit", "total_reports": "Rate Limited", "isp": "N/A", "country": "N/A"}
    except Exception as e:
        print(Fore.RED + f"[-] AbuseIPDB Query Error: {e}")
    return None

def fetch_alienvault(ioc, ioc_type):
    if not OTX_API_KEY:
        return {"pulse_count": "Missing Key", "adversaries": [], "tags": []}
        
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    section = "IPv4" if ioc_type == "IP" else "file"
    url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{ioc}/general"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            pulse_info = data.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            
            adversaries = set()
            tags = set()
            for p in pulses:
                if p.get("adversary"): adversaries.add(p.get("adversary"))
                for t in p.get("tags", []): tags.add(t)
                
            return {
                "pulse_count": len(pulses),
                "adversaries": list(adversaries)[:5],
                "tags": list(tags)[:7]
            }
    except Exception as e:
        print(Fore.RED + f"[-] AlienVault Query Error: {e}")
    return None

# =========================================================================
# STATIC VIOLET-THEME HTML REPORT COMPILER
# =========================================================================

def generate_web_report(ioc, ioc_type, vt_data, abuse_data, otx_data):
    """Compiles intelligence profiles into an ultra-premium black & purple dashboard."""
    
    risk_score = 0
    if vt_data and isinstance(vt_data.get("malicious"), int) and vt_data["malicious"] > 0: 
        risk_score += 40
    if abuse_data and isinstance(abuse_data.get("score"), int) and abuse_data["score"] > 25: 
        risk_score += 40
    if otx_data and isinstance(otx_data.get("pulse_count"), int) and otx_data["pulse_count"] > 0: 
        risk_score += 20
    
    if risk_score >= 50:
        status_verdict = "CRITICAL / MALICIOUS INFRASTRUCTURE"
        theme_glow = "shadow-[0_0_30px_rgba(147,51,234,0.25)] border-purple-600/50 bg-purple-950/10"
        verdict_color = "text-purple-400 font-extrabold drop-shadow-[0_0_10px_rgba(147,51,234,0.5)]"
        bar_color = "from-purple-600 to-fuchsia-500"
        status_badge = "bg-purple-500/20 text-purple-300 border-purple-500/40 animate-pulse"
    else:
        status_verdict = "LOW RISK / VERIFIED CLEAN ASSET"
        theme_glow = "shadow-[0_0_20px_rgba(139,92,246,0.1)] border-slate-800 bg-slate-900/20"
        verdict_color = "text-slate-300"
        bar_color = "from-violet-600 to-purple-500"
        status_badge = "bg-slate-800 text-slate-400 border-slate-700"

    vt_malicious = vt_data["malicious"] if vt_data and isinstance(vt_data.get("malicious"), int) else 0
    vt_harmless = vt_data["harmless"] if vt_data and isinstance(vt_data.get("harmless"), int) else 0
    vt_total = vt_malicious + vt_harmless
    vt_percentage = min(100, max(0, int((vt_malicious / vt_total) * 100))) if vt_total > 0 else 0

    abuse_score = abuse_data["score"] if abuse_data and isinstance(abuse_data.get("score"), int) else 0

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SpecterScope OSINT Report: {ioc}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Plus+Jakarta+Sans:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'Plus Jakarta Sans', sans-serif; background-color: #030408; }}
        .mono {{ font-family: 'JetBrains Mono', monospace; }}
    </style>
</head>
<body class="text-slate-200 min-h-screen p-6 md:p-12 selection:bg-purple-500/30">
    <div class="max-w-6xl mx-auto space-y-8">
        
        <div class="bg-[#090d16] border border-purple-950/60 rounded-2xl p-6 shadow-2xl flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
            <div class="flex items-center gap-4">
                <div class="h-12 w-12 rounded-xl bg-gradient-to-tr from-purple-600 to-fuchsia-600 flex items-center justify-center shadow-lg shadow-purple-500/20">
                    <span class="text-xl">🛡️</span>
                </div>
                <div>
                    <h1 class="text-2xl font-extrabold tracking-tight bg-gradient-to-r from-white via-purple-200 to-slate-400 bg-clip-text text-transparent">SPECTERSCOPE OSINT</h1>
                    <p class="text-xs font-semibold uppercase tracking-widest text-purple-400/90 mt-0.5 mono">Automated Multi-Source Threat Registry</p>
                </div>
            </div>
            <div class="text-left sm:text-right mono text-[10px] text-slate-500 uppercase tracking-wider bg-black p-3 rounded-xl border border-purple-950/40">
                <p>Environment: Host Native Win11</p>
                <p class="text-purple-400 mt-0.5">Build Status: Production Optimized</p>
            </div>
        </div>

        <div class="border rounded-2xl p-6 shadow-xl transition-all duration-500 {theme_glow} grid grid-cols-1 lg:grid-cols-3 gap-6 items-center">
            <div class="lg:col-span-2 space-y-2">
                <span class="inline-block px-3 py-1 rounded-full text-xs font-bold uppercase mono tracking-wider border {status_badge}">
                    Indicator Target Identified
                </span>
                <p class="text-2xl font-bold tracking-tight text-white mono break-all bg-black px-4 py-3 rounded-xl border border-purple-950/50 shadow-inner">{ioc}</p>
                <div class="flex gap-2">
                    <span class="text-xs bg-[#090d16] border border-purple-950/40 text-purple-300 px-3 py-1 rounded-md font-bold uppercase mono">Class: {ioc_type}</span>
                </div>
            </div>
            <div class="bg-black/40 p-5 rounded-xl border border-purple-950/30 flex flex-col justify-center items-start lg:items-end">
                <h2 class="text-xs font-bold uppercase tracking-widest text-slate-400 mono">Analysis Verdict</h2>
                <p class="text-lg font-black tracking-tight mt-1 {verdict_color}">{status_verdict}</p>
                <div class="w-full mt-3">
                    <div class="flex justify-between text-[11px] font-bold text-slate-400 mono mb-1">
                        <span>RISK ELEMENT MATRIX</span>
                        <span>{risk_score}%</span>
                    </div>
                    <div class="w-full bg-black rounded-full h-1.5 border border-purple-950/40 shadow-inner overflow-hidden">
                        <div class="bg-gradient-to-r {bar_color} h-full rounded-full transition-all duration-1000" style="width: {risk_score}%"></div>
                    </div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
            
            <div class="bg-[#090d16] border border-purple-950/40 rounded-2xl p-6 shadow-xl flex flex-col justify-between">
                <div>
                    <div class="flex items-center gap-3 border-b border-purple-950/30 pb-4 mb-4">
                        <span class="text-xl">📊</span>
                        <h3 class="text-lg font-bold text-slate-200">VirusTotal Detection Ratio</h3>
                    </div>
                    {f'''<ul class="space-y-3 text-sm mono">
                        <li class="flex justify-between items-center bg-black/40 p-2.5 rounded-lg border border-purple-950/20"><span class="text-purple-300 font-semibold flex items-center gap-2"><span>🔮</span> Malicious Flags:</span> <span class="font-bold bg-purple-950/40 text-purple-400 border border-purple-900/50 px-2.5 py-0.5 rounded">{vt_data["malicious"]}</span></li>
                        <li class="flex justify-between items-center bg-black/40 p-2.5 rounded-lg border border-purple-950/20"><span class="text-fuchsia-400 flex items-center gap-2"><span>✨</span> Suspicious:</span> <span class="font-bold bg-fuchsia-950/30 text-fuchsia-400 border border-fuchsia-900/30 px-2.5 py-0.5 rounded">{vt_data["suspicious"]}</span></li>
                        <li class="flex justify-between items-center bg-black/40 p-2.5 rounded-lg border border-purple-950/20"><span class="text-slate-400 flex items-center gap-2"><span>🛡️</span> Clean / Harmless:</span> <span class="font-bold bg-slate-900 text-slate-300 border border-slate-800 px-2.5 py-0.5 rounded">{vt_data["harmless"]}</span></li>
                    </ul>''' if vt_data else '<p class="text-slate-500 text-sm italic">No records returned or engine query timeout.</p>'}
                </div>
                {f'''<div class="mt-6 pt-4 border-t border-purple-950/30">
                    <div class="flex justify-between text-[10px] font-bold text-slate-400 mono mb-1">
                        <span>ENGINE DETECTION CONVERGENCE RATIO</span>
                        <span>{vt_percentage}%</span>
                    </div>
                    <div class="w-full bg-black rounded-full h-1 border border-purple-950/40 overflow-hidden">
                        <div class="bg-gradient-to-r from-purple-600 to-fuchsia-500 h-full rounded-full" style="width: {vt_percentage}%"></div>
                    </div>
                </div>''' if vt_data else ''}
            </div>

            <div class="bg-[#090d16] border border-purple-950/40 rounded-2xl p-6 shadow-xl">
                <div class="flex items-center gap-3 border-b border-purple-950/30 pb-4 mb-4">
                    <span class="text-xl">⚠️</span>
                    <h3 class="text-lg font-bold text-slate-200">AbuseIPDB Activity Profile</h3>
                </div>
                {f'''<ul class="space-y-3 text-sm mono">
                    <li class="flex justify-between items-center bg-black/40 p-2.5 rounded-lg border border-purple-950/20"><span>Abuse Confidence Score:</span> <span class="font-bold text-purple-400">{abuse_score}%</span></li>
                    <li class="flex justify-between items-center bg-black/40 p-2.5 rounded-lg border border-purple-950/20"><span>Recent Abuse Reports:</span> <span class="font-bold bg-black px-2 py-0.5 border border-purple-950/30 rounded">{abuse_data["total_reports"]}</span></li>
                    <li class="flex justify-between items-center bg-black/40 p-2.5 rounded-lg border border-purple-950/20"><span>Registered Net ISP:</span> <span class="truncate max-w-[180px] text-slate-300">{abuse_data["isp"]}</span></li>
                    <li class="flex justify-between items-center bg-black/40 p-2.5 rounded-lg border border-purple-950/20"><span>Geographic Origin:</span> <span class="font-bold text-fuchsia-400 flex items-center gap-1.5">🌐 {abuse_data["country"]}</span></li>
                </ul>
                <div class="mt-5">
                    <div class="w-full bg-black rounded-full h-1 border border-purple-950/30 overflow-hidden">
                        <div class="bg-gradient-to-r from-violet-600 to-fuchsia-500 h-full rounded-full" style="width: {abuse_score}%"></div>
                    </div>
                </div>''' if ioc_type == "IP" and abuse_data else '<p class="text-slate-500 text-sm italic p-4 bg-black/30 border border-dashed border-purple-950/20 rounded-xl">Not applicable. AbuseIPDB profiles evaluate network address configurations exclusively.</p>'}
            </div>
        </div>

        <div class="bg-[#090d16] border border-purple-950/40 rounded-2xl p-6 shadow-xl">
            <div class="flex items-center gap-3 border-b border-purple-950/30 pb-4 mb-4">
                <span class="text-xl">🗂️</span>
                <h3 class="text-lg font-bold text-slate-200">AlienVault OTX Threat Pulse Linkages</h3>
            </div>
            {f'''<div class="space-y-5">
                <p class="text-sm tracking-wide text-slate-300">Active Threat System Correlated References: <span class="font-bold text-fuchsia-400 bg-black px-2.5 py-0.5 border border-purple-950/40 rounded mx-1 mono">{otx_data["pulse_count"]} pulses</span></p>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                    <div class="bg-black/40 p-4 rounded-xl border border-purple-950/20 space-y-2">
                        <h4 class="text-[10px] font-bold uppercase tracking-widest text-slate-400 mono">Identified Adversary Campaign Groups</h4>
                        <div class="flex flex-wrap gap-1.5 pt-1">
                            {" ".join([f'<span class="bg-purple-500/10 text-purple-400 border border-purple-500/20 px-2.5 py-1 rounded-md text-xs mono font-bold">{adv}</span>' for adv in otx_data["adversaries"]]) if otx_data["adversaries"] else '<span class="text-slate-500 text-xs italic mono">No actor names flagged.</span>'}
                        </div>
                    </div>
                    
                    <div class="bg-black/40 p-4 rounded-xl border border-purple-950/20 space-y-2">
                        <h4 class="text-[10px] font-bold uppercase tracking-widest text-slate-400 mono">Threat Infrastructure Context Tags</h4>
                        <div class="flex flex-wrap gap-1.5 pt-1">
                            {" ".join([f'<span class="bg-black text-slate-400 border border-purple-950/30 px-2 py-0.5 rounded text-xs font-mono">#{tag}</span>' for tag in otx_data["tags"]]) if otx_data["tags"] else '<span class="text-slate-500 text-xs italic mono">None cataloged.</span>'}
                        </div>
                    </div>
                </div>
            </div>''' if otx_data else '<p class="text-slate-500 text-sm italic">No open threat matrix pulse linkages located.</p>'}
        </div>

    </div>
</body>
</html>
"""
    report_filename = "threat_report.html"
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    print(Fore.GREEN + f"\n[+] Success! Consolidated dashboard written safely to '{report_filename}'")
    webbrowser.open(os.path.abspath(report_filename))


# =========================================================================
# MAIN INTERACTIVE MENU LOOP
# =========================================================================

def main():
    print(Fore.MAGENTA + "==================================================")
    print(Fore.MAGENTA + "🔮 SPECTERSCOPE OSINT ENGINE ACTIVE              ")
    print(Fore.MAGENTA + "==================================================\n")
    
    ioc_input = input("Enter an Indicator of Compromise (IP or File Hash): ").strip()
    
    if not ioc_input:
        print(Fore.RED + "[-] Error: Input field cannot be left blank.")
        return

    ioc_type = detect_ioc_type(ioc_input)
    
    if not ioc_type:
        print(Fore.RED + "[-] Error: Invalid input formatting. Must be IPv4, MD5, or SHA256.")
        return
        
    print(Fore.GREEN + f"[+] Target Confirmed: {ioc_input} | Type Identified: {ioc_type}\n")
    print(Fore.MAGENTA + "[*] Contacting global OSINT feeds across active sessions...")

    vt_results = fetch_virustotal(ioc_input, ioc_type)
    otx_results = fetch_alienvault(ioc_input, ioc_type)
    
    abuse_results = None
    if ioc_type == "IP":
        abuse_results = fetch_abuseipdb(ioc_input)

    generate_web_report(ioc_input, ioc_type, vt_results, abuse_results, otx_results)


if __name__ == "__main__":
    import traceback
    try:
        main()
    except Exception as e:
        print(f"\n{Fore.RED}[-] CRITICAL AUTOMATION ENGINE FAILURE:")
        traceback.print_exc()