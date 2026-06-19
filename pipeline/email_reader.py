import imaplib
import email
from email.header import decode_header
from dotenv import load_dotenv
import os

# Load credentials from .env file
load_dotenv()

EMAIL = os.getenv("EMAIL_ADDRESS")
PASSWORD = os.getenv("EMAIL_PASSWORD").replace(" ", "")

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

def fetch_latest_emails(mail, count=5):
    """Fetch the latest emails from inbox"""
    emails = []
    
    # Select inbox
    mail.select("inbox")
    
    # Search for all emails
    status, messages = mail.search(None, "ALL")
    email_ids = messages[0].split()
    
    # Get the latest ones
    latest_ids = email_ids[-count:]
    
    print(f"\n📧 Fetching last {count} emails...\n")
    
    for email_id in reversed(latest_ids):
        # Fetch email by ID
        status, msg_data = mail.fetch(email_id, "(RFC822)")
        
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                
                # Decode subject
                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding or "utf-8")
                
                # Get sender
                sender = msg.get("From")
                
                # Get body
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode()
                            break
                else:
                    body = msg.get_payload(decode=True).decode()
                
                # Store email data
                email_data = {
                    "subject": subject,
                    "sender": sender,
                    "body": body[:1000],  # First 1000 chars
                }
                
                emails.append(email_data)
                
                # Print preview
                print(f"📨 From: {sender}")
                print(f"📌 Subject: {subject}")
                print(f"📝 Preview: {body[:100]}...")
                print("-" * 50)
    
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