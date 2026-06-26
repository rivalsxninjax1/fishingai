import chromadb
from chromadb.utils import embedding_functions
import os

# Initialize ChromaDB
client = chromadb.PersistentClient(path="data/scamdb")

# Use default embedding function
embedding_func = embedding_functions.DefaultEmbeddingFunction()

# Create or load collection
collection = client.get_or_create_collection(
    name="scam_patterns",
    embedding_function=embedding_func
)

# ============================================================
# SCAM PATTERNS DATABASE
# Includes global + Nepal government context specific patterns
# ============================================================

scam_patterns = [

    # ─────────────────────────────────────────
    # 1. PHISHING — GENERAL
    # ─────────────────────────────────────────
    {
        "id": "phish_001",
        "text": "Your account has been compromised. Click here immediately to verify your credentials or your account will be permanently suspended within 24 hours.",
        "category": "Phishing",
        "risk": "HIGH",
        "explanation": "Creates urgency and fear to trick user into clicking malicious link"
    },
    {
        "id": "phish_002",
        "text": "Dear user, we have detected suspicious activity on your account. Please confirm your identity by providing your username and password immediately.",
        "category": "Phishing",
        "risk": "HIGH",
        "explanation": "Legitimate services never ask for passwords via email"
    },
    {
        "id": "phish_003",
        "text": "Your password will expire in 24 hours. Click the link below to reset your password and avoid losing access to your account.",
        "category": "Phishing",
        "risk": "HIGH",
        "explanation": "Fake password expiry used to steal credentials"
    },

    # ─────────────────────────────────────────
    # 2. NIGERIAN PRINCE / ADVANCE FEE FRAUD
    # ─────────────────────────────────────────
    {
        "id": "nigerian_001",
        "text": "I am a prince from Nigeria and I have $10 million USD that I need to transfer to a safe account. I will give you 30% commission if you help me. Please send your bank account details.",
        "category": "Advance Fee Fraud",
        "risk": "HIGH",
        "explanation": "Classic advance fee fraud promising large reward for bank details"
    },
    {
        "id": "nigerian_002",
        "text": "I am a dying wealthy businessman and I want to donate my fortune of $5 million to a trustworthy person. You have been selected. Please respond urgently.",
        "category": "Advance Fee Fraud",
        "risk": "HIGH",
        "explanation": "Emotional manipulation to extract money or personal information"
    },

    # ─────────────────────────────────────────
    # 3. FAKE INVOICE / FINANCIAL FRAUD
    # ─────────────────────────────────────────
    {
        "id": "invoice_001",
        "text": "Please find attached invoice #INV-2024-001 for services rendered. Payment of $5,000 is overdue. Please wire transfer immediately to avoid legal action.",
        "category": "Fake Invoice",
        "risk": "HIGH",
        "explanation": "Fake invoice scam targeting businesses and government offices"
    },
    {
        "id": "invoice_002",
        "text": "This is a reminder that your payment is overdue. To avoid penalties and legal proceedings, please make an immediate wire transfer to the following account.",
        "category": "Fake Invoice",
        "risk": "HIGH",
        "explanation": "Threatens legal action to pressure immediate payment"
    },

    # ─────────────────────────────────────────
    # 4. CEO / AUTHORITY IMPERSONATION
    # ─────────────────────────────────────────
    {
        "id": "ceo_001",
        "text": "This is the CEO. I need you to urgently process a wire transfer of $50,000 to this account. This is confidential, do not discuss with anyone else in the office.",
        "category": "CEO Impersonation",
        "risk": "HIGH",
        "explanation": "BEC attack impersonating authority figure demanding secret action"
    },
    {
        "id": "ceo_002",
        "text": "I am currently in a meeting and need you to purchase gift cards worth $2,000 immediately. This is urgent. I will explain later. Keep this between us.",
        "category": "CEO Impersonation",
        "risk": "HIGH",
        "explanation": "Gift card scam disguised as urgent request from authority"
    },

    # ─────────────────────────────────────────
    # 5. NEPAL GOVERNMENT SPECIFIC SCAMS
    # ─────────────────────────────────────────
    {
        "id": "nepal_gov_001",
        "text": "This is an urgent notice from the Ministry of Finance Nepal. Your department has been selected for a special budget allocation of NPR 50,00,000. Please provide your personal bank account details to process the transfer.",
        "category": "Nepal Government Impersonation",
        "risk": "CRITICAL",
        "explanation": "Impersonates Nepal Ministry of Finance to steal bank credentials. Government funds are never transferred to personal accounts."
    },
    {
        "id": "nepal_gov_002",
        "text": "Notice from Nepal Rastra Bank. Your account has been flagged for suspicious transactions. You must immediately verify your account by clicking the link and providing your citizenship number and bank details.",
        "category": "Nepal Government Impersonation",
        "risk": "CRITICAL",
        "explanation": "Impersonates Nepal Rastra Bank (central bank). NRB never requests personal details via email."
    },
    {
        "id": "nepal_gov_003",
        "text": "Congratulations! The Government of Nepal has selected you for the civil servant bonus scheme. To receive NPR 1,00,000 please provide your bank account number and citizenship certificate number.",
        "category": "Nepal Government Impersonation",
        "risk": "CRITICAL",
        "explanation": "Fake government bonus scheme targeting civil servants to steal identity and banking information"
    },
    {
        "id": "nepal_gov_004",
        "text": "This is a notice from Inland Revenue Department Nepal. You have unpaid taxes of NPR 2,50,000. Pay immediately via the following link to avoid arrest and criminal proceedings.",
        "category": "Nepal Tax Scam",
        "risk": "CRITICAL",
        "explanation": "Impersonates IRD Nepal threatening arrest to extort money. IRD never threatens arrest via email."
    },
    {
        "id": "nepal_gov_005",
        "text": "Dear Officer, this is the Office of the Prime Minister. You have been selected for a special overseas training program. Please pay NPR 50,000 registration fee to confirm your seat.",
        "category": "Nepal Government Impersonation",
        "risk": "CRITICAL",
        "explanation": "Fake training program targeting government officers. Official training never requires personal fee payment."
    },
    {
        "id": "nepal_gov_006",
        "text": "This is Public Service Commission Nepal. Your exam result has been processed. To receive your appointment letter please pay NPR 10,000 processing fee to the following eSewa number.",
        "category": "Nepal PSC Scam",
        "risk": "CRITICAL",
        "explanation": "Impersonates Lok Sewa Aayog (PSC). PSC never charges fees for appointment letters via eSewa or personal accounts."
    },
    {
        "id": "nepal_gov_007",
        "text": "Nepal Police Cyber Bureau: Your device has been found involved in illegal activities. Pay NPR 25,000 fine immediately via eSewa to avoid arrest. Case number: NP-2024-XXX.",
        "category": "Nepal Police Impersonation",
        "risk": "CRITICAL",
        "explanation": "Impersonates Nepal Police to extort money via fear. Police never collect fines via eSewa or email."
    },
    {
        "id": "nepal_gov_008",
        "text": "Notice from Department of Passport Nepal. Your passport application requires additional processing fee of NPR 5,000. Pay via the link below within 24 hours or your application will be cancelled.",
        "category": "Nepal Government Impersonation",
        "risk": "CRITICAL",
        "explanation": "Fake passport fee scam. Department of Passport has fixed official fees paid only at official counters."
    },
    {
        "id": "nepal_gov_009",
        "text": "This is CIAA Nepal (Commission for Investigation of Abuse of Authority). You are under investigation for corruption. To settle this case privately pay NPR 5,00,000 to the following account.",
        "category": "Nepal Authority Impersonation",
        "risk": "CRITICAL",
        "explanation": "Impersonates CIAA Nepal to extort money. CIAA never settles cases privately or via bank transfer."
    },
    {
        "id": "nepal_gov_010",
        "text": "Dear Government Employee, Nepal Government Provident Fund (NPPF) requires you to update your KYC immediately. Click the link and enter your PAN number, citizenship number and bank details.",
        "category": "Nepal KYC Scam",
        "risk": "CRITICAL",
        "explanation": "Fake KYC update targeting government employees to steal identity documents and banking credentials."
    },

    # ─────────────────────────────────────────
    # 6. NEPAL DIGITAL PAYMENT SCAMS
    # ─────────────────────────────────────────
    {
        "id": "nepal_digital_001",
        "text": "Congratulations! Your eSewa account has won NPR 50,000 in our lucky draw. Click the link and enter your eSewa PIN and password to claim your prize.",
        "category": "Nepal Digital Payment Scam",
        "risk": "CRITICAL",
        "explanation": "Fake eSewa prize scam to steal digital wallet credentials. eSewa never asks for PIN via email."
    },
    {
        "id": "nepal_digital_002",
        "text": "Your Khalti account has been suspended. To reactivate please verify your account by providing your Khalti MPIN and linked mobile number immediately.",
        "category": "Nepal Digital Payment Scam",
        "risk": "CRITICAL",
        "explanation": "Fake Khalti suspension scam. Khalti never requests MPIN via email."
    },
    {
        "id": "nepal_digital_003",
        "text": "ConnectIPS alert: Unusual transaction detected on your account. Verify your identity immediately by entering your ConnectIPS username and password on the link below.",
        "category": "Nepal Digital Payment Scam",
        "risk": "CRITICAL",
        "explanation": "Impersonates ConnectIPS Nepal to steal banking credentials."
    },

    # ─────────────────────────────────────────
    # 7. FAKE PRIZE / LOTTERY
    # ─────────────────────────────────────────
    {
        "id": "prize_001",
        "text": "You have been selected as the winner of our international lottery. You have won $500,000 USD. To claim your prize please pay a processing fee of $500 and provide your personal details.",
        "category": "Lottery Scam",
        "risk": "HIGH",
        "explanation": "Classic lottery scam requiring upfront fee to claim fake prize"
    },
    {
        "id": "prize_002",
        "text": "Congratulations! You have won an iPhone 15 Pro in our lucky draw. Click the link to claim your prize. Only pay NPR 500 shipping fee.",
        "category": "Lottery Scam",
        "risk": "HIGH",
        "explanation": "Fake prize requiring small shipping fee — leads to identity theft or larger charges"
    },

    # ─────────────────────────────────────────
    # 8. JOB / EMPLOYMENT SCAMS
    # ─────────────────────────────────────────
 {
        "id": "job_001",
        "text": "You have been selected for a high paying job in Qatar. Salary NPR 80,000 per month plus accommodation. Pay NPR 80,000 visa processing fee and medical clearance fee to confirm your placement immediately via eSewa.",
        "category": "Job Scam",
        "risk": "CRITICAL",
        "explanation": "Fake foreign employment scam targeting Nepal job seekers. Requires upfront payment via eSewa — legitimate agencies never require personal payment."
    },
    {
        "id": "job_002",
        "text": "Work from home opportunity. Earn NPR 50,000 per month by working just 2 hours daily. Registration fee of NPR 5,000 required to get started. Limited seats available.",
        "category": "Job Scam",
        "risk": "HIGH",
        "explanation": "Fake work from home scheme requiring upfront registration fee"
    },
    {
        "id": "job_003",
        "text": "Urgent job placement in UAE Dubai Qatar. High salary guaranteed. Pay visa fee medical fee insurance fee immediately to secure your position. Limited seats. Pay via eSewa fonepay.",
        "category": "Job Scam",
        "risk": "CRITICAL",
        "explanation": "Foreign job scam requiring multiple upfront fees. Legitimate foreign employment never requires personal fee payment before joining."
    },

    # ─────────────────────────────────────────
    # 9. MALWARE / ATTACHMENT SCAMS
    # ─────────────────────────────────────────
    {
        "id": "malware_001",
        "text": "Please find the attached document regarding your recent transaction. Open the attachment to view the details. Password: 1234",
        "category": "Malware",
        "risk": "HIGH",
        "explanation": "Password protected attachment is a common technique to bypass email security scanners"
    },
    {
        "id": "malware_002",
        "text": "Your computer has been infected with a virus. Download and run the attached security tool immediately to remove the threat and protect your data.",
        "category": "Malware",
        "risk": "HIGH",
        "explanation": "Fake security tool that installs actual malware on the victim's device"
    },

    # ─────────────────────────────────────────
    # 10. ROMANCE / SOCIAL ENGINEERING
    # ─────────────────────────────────────────
    {
        "id": "romance_001",
        "text": "Hello dear, I found your profile and I think we have a connection. I am a US Army officer currently deployed. I need your help to transfer my savings of $200,000 out of the country.",
        "category": "Romance Scam",
        "risk": "HIGH",
        "explanation": "Military romance scam combining emotional manipulation with advance fee fraud"
    },
]

def build_database():
    """Load all scam patterns into ChromaDB"""
    
    print("🔨 Building scam pattern database...")
    
    # Check if already populated
    existing = collection.count()
    if existing > 0:
        print(f"✅ Database already has {existing} patterns loaded!")
        return
    
    # Add all patterns
    documents = [p["text"] for p in scam_patterns]
    ids = [p["id"] for p in scam_patterns]
    metadatas = [
        {
            "category": p["category"],
            "risk": p["risk"],
            "explanation": p["explanation"]
        }
        for p in scam_patterns
    ]
    
    collection.add(
        documents=documents,
        ids=ids,
        metadatas=metadatas
    )
    
    print(f"✅ Successfully loaded {len(scam_patterns)} scam patterns!")
    print("\n📊 Categories loaded:")
    categories = set(p["category"] for p in scam_patterns)
    for cat in categories:
        count = sum(1 for p in scam_patterns if p["category"] == cat)
        print(f"   • {cat}: {count} patterns")

def search_patterns(query_text, n_results=3):
    """Search database for patterns similar to input text"""
    results = collection.query(
        query_texts=[query_text],
        n_results=n_results
    )
    return results

if __name__ == "__main__":
    build_database()

def search_patterns_with_distance(query_text, n_results=3):
    """Search database and return distances for confidence scoring"""
    results = collection.query(
        query_texts=[query_text],
        n_results=n_results,
        include=["documents", "metadatas", "distances"]
    )
    return results