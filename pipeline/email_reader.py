import imaplib
import email
from email.header import decode_header
from dotenv import load_dotenv
import os


# Load credentials from .env file
load_dotenv()

EMAIL = os.getenv("EMAIL_ADDRESS", "").strip().replace(" ", "")
PASSWORD = os.getenv("EMAIL_PASSWORD", "").strip().replace(" ", "")

def connect_to_gmail():
    """Connect to Gmail using IMAP"""
    try:
        # Connect to Gmail's IMAP server
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(EMAIL, PASSWORD)
        print("✅ Connected to Gmail successfully!")
        return mail
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return None

def fetch_emails_since_checkpoint(mail, last_uid=None, first_run_limit=20):
    """
    Fetch emails using UID-based checkpoint system.

    If last_uid is None (first run ever):
        → Fetch only the most recent `first_run_limit` emails
    If last_uid is provided:
        → Fetch only emails with UID greater than last_uid

    Returns: (emails_list, highest_uid_seen)
    """
    emails = []
    mail.select("inbox")

    if last_uid is None:
        # FIRST RUN — get last N emails only
        status, messages = mail.uid("search", None, "ALL")
        uids = messages[0].split()

        if not uids:
            return emails, None

        target_uids = uids[-first_run_limit:]
        print(f"\n🆕 First run — analyzing last {len(target_uids)} emails only")
    else:
        # NORMAL RUN — get only emails newer than checkpoint
        status, messages = mail.uid(
            "search", None, f"UID {int(last_uid) + 1}:*"
        )
        uids = messages[0].split()

        # Gmail quirk: searching UID range can return the last_uid itself
        # if nothing newer exists — filter that out
        target_uids = [u for u in uids if int(u) > int(last_uid)]

        if not target_uids:
            print("📭 No new emails since last check")
            return emails, last_uid

        # SAFETY CAP — never try to process more than 30 at once
        # Prevents timeout if checkpoint is ever wrong/stale
        if len(target_uids) > 30:
            print(f"⚠️  Found {len(target_uids)} emails — capping to most recent 30 for safety")
            target_uids = target_uids[-30:]
        else:
            print(f"\n📧 Found {len(target_uids)} new email(s) since last check")

    highest_uid = last_uid

    for uid in target_uids:
        status, msg_data = mail.uid("fetch", uid, "(RFC822)")

        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])

                message_id = msg.get("Message-ID", "").strip()
                if not message_id:
                    # Build a guaranteed-unique fallback using UID + sender + date
                    # UID alone is enough since it's unique per mailbox
                    message_id = f"uid-{uid.decode() if isinstance(uid, bytes) else uid}"

                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding or "utf-8")

                sender = msg.get("From")
                date_header = msg.get("Date", "")

                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            try:
                                body = part.get_payload(decode=True).decode()
                                break
                            except Exception:
                                pass
                else:
                    try:
                        body = msg.get_payload(decode=True).decode()
                    except Exception:
                        body = ""

               # Detect Gmail category using X-GM-LABELS (Gmail-specific IMAP extension)
                category = "primary"
                try:
                    label_status, label_data = mail.uid("fetch", uid, "(X-GM-LABELS)")
                    label_text = str(label_data[0]) if label_data else ""
                    if "Promotions" in label_text or "\\\\CategoryPromotions" in label_text:
                        category = "promotions"
                    elif "Updates" in label_text or "\\\\CategoryUpdates" in label_text:
                        category = "updates"
                    elif "Social" in label_text or "\\\\CategorySocial" in label_text:
                        category = "social"
                    elif "Forums" in label_text or "\\\\CategoryForums" in label_text:
                        category = "forums"
                except Exception:
                    category = "primary"
                     # Extract attachments metadata
                attachments = []
                if msg.is_multipart():
                    for part in msg.walk():
                        content_disposition = str(part.get("Content-Disposition", ""))
                        if "attachment" in content_disposition:
                            filename = part.get_filename()
                            if filename:
                                payload = part.get_payload(decode=True)
                                attachments.append({
                                    "filename": filename,
                                    "size": len(payload) if payload else 0,
                                    "content_type": part.get_content_type(),
                                    "payload": payload[:50000] if payload else b""
                                })

                emails.append({
                    "uid": uid.decode() if isinstance(uid, bytes) else str(uid),
                    "message_id": message_id,
                    "subject": subject,
                    "sender": sender,
                    "body": body[:2000],
                    "date": date_header,
                    "gmail_category": category,
                    "attachments": attachments,   # ← NEW
                })
        uid_int = int(uid)
        if highest_uid is None or uid_int > int(highest_uid):
            highest_uid = str(uid_int)

    return emails, highest_uid
def main():
    # Connect to Gmail
    mail = connect_to_gmail()
    
    if mail:
        # Fetch latest 5 emails
        emails = fetch_latest_emails(mail, count=5)
        print(f"\n✅ Successfully fetched {len(emails)} emails!")
        mail.logout()
        return emails

if __name__ == "__main__":
    main()