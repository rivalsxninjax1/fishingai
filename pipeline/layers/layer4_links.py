import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import asyncio
import aiohttp
import re
import tldextract

# URL shorteners that hide real destination
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "buff.ly", "rebrand.ly", "short.io",
    "tiny.cc", "is.gd", "v.gd", "rb.gy"
}

# Suspicious patterns in URLs
SUSPICIOUS_URL_PATTERNS = [
    r'login', r'verify', r'secure', r'account',
    r'update', r'confirm', r'validate', r'signin',
    r'banking', r'payment', r'credential',
    # Nepal specific
    r'nrb', r'esewa', r'khalti', r'fonepay',
    r'nepal.*gov', r'gov.*nepal',
]


def extract_urls(text: str) -> list:
    """Extract all URLs from email text"""
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|'
        r'(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    return url_pattern.findall(text)


def analyze_url_static(url: str) -> dict:
    """
    Static URL analysis without making HTTP requests
    Fast — runs instantly
    """
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    issues = []

    # IP address instead of domain name
    ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    if ip_pattern.match(url):
        issues.append("URL uses IP address instead of domain name")

    # URL shortener
    if domain in URL_SHORTENERS:
        issues.append(f"URL shortener hides real destination: {domain}")

    # Suspicious keywords in URL
    url_lower = url.lower()
    for pattern in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, url_lower):
            issues.append(f"Suspicious keyword in URL: '{pattern}'")
            break

    # Excessive subdomains (hiding real domain)
    subdomain_count = len(extracted.subdomain.split(".")) if extracted.subdomain else 0
    if subdomain_count > 2:
        issues.append(f"Suspicious number of subdomains: {subdomain_count}")

    # Encoded characters (hiding real URL)
    if url.count("%") > 3:
        issues.append("URL contains excessive encoded characters")

    # Very long URL (hiding real destination)
    if len(url) > 200:
        issues.append(f"Suspiciously long URL: {len(url)} characters")

    return {
        "url": url,
        "domain": domain,
        "issues": issues,
        "risk_level": "HIGH" if len(issues) >= 2 else "MEDIUM" if issues else "LOW"
    }


async def check_url_redirect(url: str, session: aiohttp.ClientSession) -> dict:
    """
    Follow URL redirects to find final destination
    Many phishing URLs redirect through legitimate sites
    """
    try:
        async with session.head(
            url,
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=5),
            ssl=False
        ) as response:
            final_url = str(response.url)
            redirect_count = len(response.history)

            final_domain = tldextract.extract(final_url).registered_domain
            original_domain = tldextract.extract(url).registered_domain

            domain_changed = final_domain != original_domain

            return {
                "original_url": url,
                "final_url": final_url,
                "redirect_count": redirect_count,
                "domain_changed": domain_changed,
                "original_domain": original_domain,
                "final_domain": final_domain,
                "suspicious": domain_changed and redirect_count > 0
            }

    except Exception as e:
        return {
            "original_url": url,
            "final_url": url,
            "redirect_count": 0,
            "domain_changed": False,
            "suspicious": False,
            "error": str(e)
        }


async def run(email_data: dict) -> dict:
    """LAYER 4 — Link Scanner"""

    body = email_data.get("body", "")
    subject = email_data.get("subject", "")
    full_text = f"{subject} {body}"

    urls = extract_urls(full_text)

    if not urls:
        return {
            "layer": "Link Scanner",
            "risk_points": 0,
            "max_points": 15,
            "findings": ["✅ No URLs found in email"],
            "details": {"urls_found": 0},
            "early_exit": False
        }

    risk_points = 0
    findings = []
    url_results = []

    # Static analysis — instant
    for url in urls[:10]:  # Max 10 URLs
        result = analyze_url_static(url)
        url_results.append(result)

        if result["risk_level"] == "HIGH":
            risk_points += 8
            for issue in result["issues"]:
                findings.append(f"🚨 {issue}: {url[:80]}")
        elif result["risk_level"] == "MEDIUM":
            risk_points += 4
            for issue in result["issues"]:
                findings.append(f"⚠️ {issue}")

    # Dynamic redirect checking — async, all at once
    try:
        async with aiohttp.ClientSession() as session:
            redirect_tasks = [
                check_url_redirect(url, session)
                for url in urls[:5]  # Check top 5 URLs
            ]
            redirect_results = await asyncio.gather(
                *redirect_tasks,
                return_exceptions=True
            )

            for result in redirect_results:
                if isinstance(result, dict) and result.get("suspicious"):
                    risk_points += 10
                    findings.append(
                        f"🚨 REDIRECT DECEPTION: URL redirects from "
                        f"'{result['original_domain']}' to "
                        f"'{result['final_domain']}'"
                    )
    except Exception:
        pass

    if not findings:
        findings.append(f"✅ {len(urls)} URL(s) checked — no suspicious links found")

    return {
        "layer": "Link Scanner",
        "risk_points": min(risk_points, 15),
        "max_points": 15,
        "findings": findings,
        "details": {
            "urls_found": len(urls),
            "urls_checked": url_results
        },
        "early_exit": risk_points >= 15
    }