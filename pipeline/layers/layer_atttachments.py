import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import asyncio
import re

# ─────────────────────────────────────────
# DANGEROUS FILE EXTENSIONS
# ─────────────────────────────────────────
DANGEROUS_EXTENSIONS = {
    # Executables
    ".exe", ".bat", ".cmd", ".com", ".pif", ".scr", ".msi",
    # Scripts
    ".vbs", ".vbe", ".js", ".jse", ".ps1", ".psm1", ".psd1",
    ".sh", ".bash", ".py", ".rb", ".pl",
    # Java
    ".jar", ".class",
    # Web
    ".html", ".htm", ".php", ".asp", ".aspx",
    # Archives (suspicious when unexpected)
    ".iso", ".img",
    # Office macros
    ".xlsm", ".xltm", ".xlam",
    ".docm", ".dotm",
    ".pptm", ".potm", ".ppam",
}

SUSPICIOUS_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".gz", ".tar",  # Archives — check if password protected
    ".pdf",   # Check for embedded JavaScript
    ".doc", ".xls", ".ppt",  # Old Office formats — can contain macros
    ".svg",   # Can contain embedded scripts
    ".xml",   # Can contain malicious payloads
}

# File signatures (magic bytes) for type verification
FILE_SIGNATURES = {
    b"\x4D\x5A": "Windows Executable (EXE/DLL)",
    b"\x50\x4B\x03\x04": "ZIP Archive",
    b"\x50\x4B\x05\x06": "ZIP Archive (empty)",
    b"\x25\x50\x44\x46": "PDF Document",
    b"\xD0\xCF\x11\xE0": "Microsoft Office (Old Format)",
    b"\x52\x61\x72\x21": "RAR Archive",
    b"\x7F\x45\x4C\x46": "Linux Executable (ELF)",
    b"\xCA\xFE\xBA\xBE": "Java Class File",
    b"\x4D\x53\x43\x46": "Microsoft Cabinet File",
}


def check_extension_mismatch(filename: str, payload: bytes) -> dict:
    """
    Check if file's real type matches its extension
    A PDF that's actually an EXE is a classic malware trick
    """
    if not filename or not payload:
        return {"mismatch": False}

    # Get claimed extension
    _, ext = os.path.splitext(filename.lower())

    # Check real file type from magic bytes
    real_type = None
    for signature, file_type in FILE_SIGNATURES.items():
        if payload[:len(signature)] == signature:
            real_type = file_type
            break

    if not real_type:
        return {"mismatch": False, "real_type": "Unknown"}

    # Check for mismatches
    mismatch = False
    detail = ""

    if ext == ".pdf" and "Executable" in real_type:
        mismatch = True
        detail = f"File claims to be PDF but is actually {real_type}"
    elif ext in [".doc", ".docx", ".xls", ".xlsx"] and "Executable" in real_type:
        mismatch = True
        detail = f"File claims to be Office document but is actually {real_type}"
    elif ext in [".jpg", ".png", ".gif"] and "Executable" in real_type:
        mismatch = True
        detail = f"File disguised as image but is actually {real_type}"

    return {
        "mismatch": mismatch,
        "claimed_extension": ext,
        "real_type": real_type,
        "detail": detail
    }


def check_double_extension(filename: str) -> dict:
    """
    Detect double extension attacks
    invoice.pdf.exe shows as "invoice.pdf" in some email clients
    """
    if not filename:
        return {"has_double_ext": False}

    parts = filename.split(".")
    if len(parts) >= 3:
        second_last_ext = f".{parts[-2].lower()}"
        last_ext = f".{parts[-1].lower()}"

        if last_ext in DANGEROUS_EXTENSIONS:
            return {
                "has_double_ext": True,
                "detail": f"Double extension: shows as '{second_last_ext}' but is actually '{last_ext}'",
                "filename": filename
            }

    return {"has_double_ext": False}


def check_pdf_javascript(payload: bytes) -> dict:
    """
    Check PDF for embedded JavaScript
    Malicious PDFs often contain JS to exploit PDF readers
    """
    if not payload:
        return {"has_js": False}

    try:
        content = payload.decode("latin-1", errors="ignore").lower()
        js_indicators = [
            "/javascript", "/js", "eval(", "unescape(",
            "shellcode", "/openaction", "/aa"
        ]

        found = [ind for ind in js_indicators if ind in content]

        return {
            "has_js": len(found) > 0,
            "indicators": found[:3]
        }
    except Exception:
        return {"has_js": False}


def check_office_macros(filename: str, payload: bytes) -> dict:
    """
    Detect macro-enabled Office files
    Old .doc/.xls can contain macros too
    """
    if not filename:
        return {"has_macros": False}

    _, ext = os.path.splitext(filename.lower())

    # New macro-enabled formats are obvious from extension
    if ext in {".xlsm", ".xltm", ".xlam", ".docm", ".dotm", ".pptm", ".potm"}:
        return {
            "has_macros": True,
            "detail": f"Macro-enabled Office file: {ext}",
            "certain": True
        }

    # Old formats — check for VBA signature
    if ext in {".doc", ".xls", ".ppt"} and payload:
        # VBA macro signature in old Office files
        vba_signatures = [b"VBA", b"vba", b"Macros", b"_VBA_PROJECT"]
        for sig in vba_signatures:
            if sig in payload[:8192]:
                return {
                    "has_macros": True,
                    "detail": f"Old Office format with VBA macros detected: {ext}",
                    "certain": False
                }

    return {"has_macros": False}


def check_password_protected(filename: str, payload: bytes) -> dict:
    """
    Detect password-protected archives
    Used to hide malware from email scanners
    """
    if not filename or not payload:
        return {"is_protected": False}

    _, ext = os.path.splitext(filename.lower())

    if ext in {".zip", ".zipx"}:
        # Check ZIP general purpose bit flag for encryption (bit 0)
        try:
            # Look for local file headers and check encryption flag
            i = 0
            while i < len(payload) - 30:
                if payload[i:i+4] == b"PK\x03\x04":
                    flags = int.from_bytes(payload[i+6:i+8], "little")
                    if flags & 0x1:  # Encryption flag
                        return {
                            "is_protected": True,
                            "detail": "Password-protected ZIP archive — content hidden from scanners"
                        }
                i += 1
        except Exception:
            pass

    return {"is_protected": False}


async def run(email_data: dict) -> dict:
    """
    ATTACHMENT SCANNER
    Analyzes all email attachments for malware indicators
    Runs entirely offline — no external APIs needed
    """
    attachments = email_data.get("attachments", [])

    if not attachments:
        return {
            "layer": "Attachment Scanner",
            "risk_points": 0,
            "max_points": 25,
            "findings": ["✅ No attachments found"],
            "details": {"attachment_count": 0},
            "early_exit": False
        }

    risk_points = 0
    findings = []
    attachment_results = []

    print(f"   📎 Scanning {len(attachments)} attachment(s)...")

    for attachment in attachments:
        filename = attachment.get("filename", "unknown")
        payload = attachment.get("payload", b"")
        size = attachment.get("size", 0)
        content_type = attachment.get("content_type", "")

        result = {
            "filename": filename,
            "size": size,
            "issues": []
        }

        _, ext = os.path.splitext(filename.lower())

        # ── CHECK 1: Dangerous extension ──
        if ext in DANGEROUS_EXTENSIONS:
            risk_points += 25
            result["issues"].append(f"Dangerous file type: {ext}")
            findings.append(f"🚨 DANGEROUS ATTACHMENT: '{filename}' — {ext} files can execute malware")

        # ── CHECK 2: Double extension ──
        double_ext = check_double_extension(filename)
        if double_ext["has_double_ext"]:
            risk_points += 25
            result["issues"].append("Double extension attack")
            findings.append(f"🚨 DOUBLE EXTENSION ATTACK: {double_ext['detail']}")

        # ── CHECK 3: Extension mismatch ──
        if payload:
            mismatch = check_extension_mismatch(filename, payload)
            if mismatch["mismatch"]:
                risk_points += 25
                result["issues"].append("File type mismatch")
                findings.append(f"🚨 FILE DISGUISE: {mismatch['detail']}")

        # ── CHECK 4: PDF JavaScript ──
        if ext == ".pdf" and payload:
            pdf_js = check_pdf_javascript(payload)
            if pdf_js["has_js"]:
                risk_points += 20
                result["issues"].append("PDF contains JavaScript")
                findings.append(
                    f"🚨 MALICIOUS PDF: '{filename}' contains embedded JavaScript — "
                    f"indicators: {', '.join(pdf_js['indicators'])}"
                )

        # ── CHECK 5: Office macros ──
        macro_check = check_office_macros(filename, payload)
        if macro_check["has_macros"]:
            risk_points += 15
            result["issues"].append("Contains macros")
            findings.append(f"⚠️ MACRO FILE: '{filename}' — {macro_check['detail']}")

        # ── CHECK 6: Password protected archive ──
        if ext in {".zip", ".rar", ".7z"} and payload:
            protected = check_password_protected(filename, payload)
            if protected["is_protected"]:
                risk_points += 15
                result["issues"].append("Password protected")
                findings.append(f"⚠️ ENCRYPTED ARCHIVE: '{filename}' — {protected['detail']}")

        # ── CHECK 7: Suspicious extension ──
        if ext in SUSPICIOUS_EXTENSIONS and not result["issues"]:
            risk_points += 3
            findings.append(f"ℹ️ Attachment type requires caution: '{filename}' ({ext})")

        # ── CHECK 8: Size anomalies ──
        if ext == ".pdf" and size < 1024:
            risk_points += 5
            findings.append(f"⚠️ Suspicious PDF size: '{filename}' is only {size} bytes — unusually small")

        attachment_results.append(result)

    if not findings:
        findings.append(f"✅ {len(attachments)} attachment(s) scanned — no threats detected")

    return {
        "layer": "Attachment Scanner",
        "risk_points": min(risk_points, 25),
        "max_points": 25,
        "findings": findings,
        "details": {
            "attachment_count": len(attachments),
            "attachments": attachment_results
        },
        "early_exit": risk_points >= 25
    }