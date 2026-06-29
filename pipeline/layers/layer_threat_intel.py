import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import asyncio
import aiohttp
import re
import dns.resolver
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), '.env'
))

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY", "")
GOOGLE_SB_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
PHISHTANK_KEY = os.getenv("PHISHTANK_KEY", "")


def extract_urls(text: str) -> list:
    """Extract all URLs from text"""
    pattern = re.compile(r'http[s]?://[^\s<>"{}|\\^`\[\]]+')
    return pattern.findall(text)


async def check_abuseipdb(ip: str, session: aiohttp.ClientSession) -> dict:
    """Check if IP is known malicious"""
    if not ABUSEIPDB_KEY or not ip:
        return {"score": 0, "checked": False}

    try:
        async with session.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90
            },
            timeout=aiohttp.ClientTimeout(total=5)
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                abuse_score = data.get("data", {}).get("abuseConfidenceScore", 0)
                country = data.get("data", {}).get("countryCode", "")
                total_reports = data.get("data", {}).get("totalReports", 0)
                return {
                    "score": abuse_score,
                    "country": country,
                    "total_reports": total_reports,
                    "checked": True,
                    "is_malicious": abuse_score > 25
                }
    except Exception as e:
        pass

    return {"score": 0, "checked": False, "is_malicious": False}


async def check_phishtank(url: str, session: aiohttp.ClientSession) -> dict:
    """Check URL against PhishTank database"""
    if not url:
        return {"is_phishing": False, "checked": False}

    try:
        async with session.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={
                "url": url,
                "format": "json",
                "app_key": PHISHTANK_KEY
            },
            timeout=aiohttp.ClientTimeout(total=5)
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                results = data.get("results", {})
                return {
                    "is_phishing": results.get("in_database", False) and results.get("valid", False),
                    "checked": True,
                    "phish_id": results.get("phish_id", "")
                }
    except Exception:
        pass

    return {"is_phishing": False, "checked": False}


async def check_google_safe_browsing(urls: list, session: aiohttp.ClientSession) -> dict:
    """Check URLs against Google Safe Browsing"""
    if not GOOGLE_SB_KEY or not urls:
        return {"threats": [], "checked": False}

    try:
        payload = {
            "client": {
                "clientId": "phishguard",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls[:10]]
            }
        }

        async with session.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_KEY}",
            json=payload,
            timeout=aiohttp.ClientTimeout(total=5)
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                matches = data.get("matches", [])
                threats = [m.get("threat", {}).get("url", "") for m in matches]
                return {
                    "threats": threats,
                    "checked": True,
                    "has_threats": len(threats) > 0
                }
    except Exception:
        pass

    return {"threats": [], "checked": False, "has_threats": False}


async def check_virustotal_url(url: str, session: aiohttp.ClientSession) -> dict:
    """Check URL against VirusTotal"""
    if not VIRUSTOTAL_KEY or not url:
        return {"malicious": 0, "checked": False}

    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        async with session.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=aiohttp.ClientTimeout(total=5)
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                return {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "checked": True,
                    "is_malicious": malicious > 2
                }
    except Exception:
        pass

    return {"malicious": 0, "checked": False, "is_malicious": False}


async def get_sender_ip(sender_domain: str) -> str:
    """Resolve sender domain to IP for AbuseIPDB check"""
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None,
            lambda: dns.resolver.resolve(sender_domain, "A")
        )
        return str(answers[0])
    except Exception:
        return ""


async def run(email_data: dict) -> dict:
    """
    LAYER — Threat Intelligence
    Checks sender IP and URLs against global threat databases
    Runs concurrently for speed
    """
    sender = email_data.get("sender", "")
    body = email_data.get("body", "")
    subject = email_data.get("subject", "")

    # Extract sender domain
    sender_email = sender
    if "<" in sender:
        sender_email = sender.split("<")[1].replace(">", "").strip()
    sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""

    # Extract URLs
    urls = extract_urls(f"{subject} {body}")

    risk_points = 0
    findings = []
    details = {}

    async with aiohttp.ClientSession() as session:

        # Build concurrent tasks
        tasks = []

        # IP reputation check
        if sender_domain:
            tasks.append(get_sender_ip(sender_domain))
        else:
            tasks.append(asyncio.coroutine(lambda: "")())

        # Google Safe Browsing for all URLs at once
        if urls:
            tasks.append(check_google_safe_browsing(urls, session))
        else:
            tasks.append(asyncio.coroutine(lambda: {"threats": [], "checked": False})())

        # PhishTank for first URL
        if urls:
            tasks.append(check_phishtank(urls[0], session))
        else:
            tasks.append(asyncio.coroutine(lambda: {"is_phishing": False})())

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process IP result
        sender_ip = results[0] if isinstance(results[0], str) else ""
        if sender_ip:
            ip_result = await check_abuseipdb(sender_ip, session)
            details["ip_check"] = ip_result
            if ip_result.get("is_malicious"):
                risk_points += 20
                findings.append(
                    f"🚨 MALICIOUS IP: Sender IP {sender_ip} has abuse score "
                    f"{ip_result['score']}/100 with {ip_result.get('total_reports', 0)} reports"
                )

        # Process Google Safe Browsing result
        gsb_result = results[1] if not isinstance(results[1], Exception) else {"threats": []}
        details["google_safe_browsing"] = gsb_result
        if gsb_result.get("has_threats"):
            risk_points += 25
            for threat_url in gsb_result["threats"][:3]:
                findings.append(
                    f"🚨 GOOGLE SAFE BROWSING: Confirmed malicious URL detected: {threat_url[:80]}"
                )

        # Process PhishTank result
        pt_result = results[2] if not isinstance(results[2], Exception) else {"is_phishing": False}
        details["phishtank"] = pt_result
        if pt_result.get("is_phishing"):
            risk_points += 25
            findings.append(
                f"🚨 PHISHTANK CONFIRMED: URL is a verified phishing page "
                f"(ID: {pt_result.get('phish_id', 'unknown')})"
            )

        # VirusTotal check for first suspicious URL
        if urls and VIRUSTOTAL_KEY:
            vt_result = await check_virustotal_url(urls[0], session)
            details["virustotal"] = vt_result
            if vt_result.get("is_malicious"):
                risk_points += 20
                findings.append(
                    f"🚨 VIRUSTOTAL: URL flagged by {vt_result['malicious']} security vendors"
                )

    if not findings:
        findings.append("✅ No threats found in global threat intelligence databases")

    return {
        "layer": "Threat Intelligence",
        "risk_points": min(risk_points, 30),
        "max_points": 30,
        "findings": findings,
        "details": details,
        "early_exit": risk_points >= 25
    }