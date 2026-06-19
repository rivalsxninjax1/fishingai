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

def fetch_latest_emails(mail, count=10):
    """Fetch only UNSEEN emails from inbox"""
    emails = []

    mail.select("inbox")

    # Only fetch UNSEEN emails — production behaviour
    status, messages = mail.search(None, "UNSEEN")
    email_ids = messages[0].split()

    if not email_ids:
        print("📭 No new unseen emails")
        return emails

    # Take latest ones up to count limit
    latest_ids = email_ids[-count:]
    print(f"\n📧 Found {len(latest_ids)} new emails...\n")

    for email_id in reversed(latest_ids):
        status, msg_data = mail.fetch(email_id, "(RFC822)")

        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])

                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding or "utf-8")

                sender = msg.get("From")

                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            try:
                                body = part.get_payload(decode=True).decode()
                                break
                            except:
                                pass
                else:
                    try:
                        body = msg.get_payload(decode=True).decode()
                    except:
                        body = ""

                email_data = {
                    "subject": subject,
                    "sender": sender,
                    "body": body[:2000],
                }

                emails.append(email_data)
                print(f"📨 Queuing: {subject[:50]}")

    return emails
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