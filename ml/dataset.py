import csv
from pathlib import Path
from typing import List, Tuple
import torch
from torch.utils.data import Dataset

from ml.tokenizer import PhishingTokenizer


class PhishingDataset(Dataset):
    """PyTorch Dataset wrapping encoded token sequences and class labels."""
    def __init__(self, texts: List[str], labels: List[int], tokenizer: PhishingTokenizer):
        self.tokenizer = tokenizer
        self.labels = labels
        self.encoded = [tokenizer.encode(t) for t in texts]

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor]:
        return (
            torch.tensor(self.encoded[idx], dtype=torch.long),
            torch.tensor(self.labels[idx], dtype=torch.long),
        )


def get_bootstrap_dataset() -> Tuple[List[str], List[int]]:
    """
    Bootstrap dataset containing diverse phishing and benign samples across real attack vectors.
    Enables immediate training, testing, and baseline validation out of the box.
    """
    # ── PHISHING SAMPLES (Label 1) ────────────────────────────────────
    phishing = [
        # BEC / Urgent Wire Transfers
        "URGENT: Wire Transfer Needed. Please process an immediate wire transfer of $45,000 for the acquisition. This is strictly confidential, do not discuss with anyone.",
        "Quick request from CEO: I am in a board meeting and cannot take calls. Send $25,000 to the attached vendor routing number today.",
        "Direct Deposit Change: Please update my bank payroll details immediately to avoid delay in salary disbursement.",
        "Important: Confidential payment required before end of day. Follow the wire instructions in the link.",
        "Re: Overdue invoice #9821. Remit payment to our updated overseas account number immediately or services will be terminated.",
        
        # Credential Harvesting / Account Suspension
        "Urgent: Your Microsoft 365 account has been suspended due to suspicious logins. Verify your credentials at https://login.ms-security-portal.xyz/verify immediately.",
        "Security Alert: Unauthorized access attempt from Russia detected. Click here to confirm your password and secure your Google account: http://192.168.1.100/auth",
        "Action Required: Your PayPal account has been limited. Confirm your identity and credit card details at https://paypal-account-verify.online/login",
        "IT Helpdesk Notice: Your email password expires in 2 hours. Keep your current password by visiting our verification portal at https://secure-it-update.top/reset",
        "Apple ID Security: Your account was used to purchase an iPhone from an unrecognized device. Cancel order by logging in here: https://apple-verify-service.com/signin",
        "Bank of America Alert: Suspicious transaction of $1,250 flagged. If this was not you, verify your online banking PIN now at http://banking-alert-secure.xyz",
        "Dropbox Notification: An urgent document 'Executive_Compensation_2026.pdf' was shared with you. Sign in with your work email to view.",
        "Office 365: You have 5 unread incoming voice messages on hold. Listen to messages by authenticating at https://voicemail-portal-auth.online",
        
        # Fake Deliveries / Refunds / Tax Lures
        "FedEx Tracking: Your package could not be delivered due to unpaid customs fee of $3.50. Update delivery address and pay here: http://fedex-parcel-update.sbs",
        "DHL Express: Shipment on hold at terminal. Download the tracking manifest invoice_delivery.pdf.exe to release your parcel.",
        "IRS Tax Notification: You have an unclaimed tax refund of $1,420. Submit your SSN and direct deposit form via our secure portal.",
        "Amazon Order Confirmation: You ordered 3x Sony PlayStation 5 for $1,499. If you did not make this purchase, click to dispute transaction immediately.",
        "HR Notice: Annual bonus calculations have been published. Open the attached macro spreadsheet 'Bonus_2026.xlsm' and enable content to calculate.",
        "DocuSign: Please review and sign 'Mutual_NDA_Revised.docm'. Enable macros to generate digital cryptographic signature.",
    ]

    # ── BENIGN SAMPLES (Label 0) ──────────────────────────────────────
    benign = [
        # Normal Corporate Correspondence
        "Meeting Tomorrow: Are we still on for the project review meeting tomorrow at 10 AM in Conference Room B?",
        "Weekly Engineering Sync: Here are the notes from today's engineering standup. Sprint velocity is on track for Thursday's demo.",
        "Pull Request #412: Please review the refactored database connection pooling changes when you get a chance.",
        "Lunch plans: Hey team, we're heading out for pizza around 12:30. Let me know if you'd like to join!",
        "Quarterly town hall agenda: The executive leadership team will host the Q3 all-hands meeting this Thursday. Submit Q&A questions in advance.",
        "Release v2.4 deployed: The customer dashboard update has been deployed to production. Monitoring metrics look healthy.",
        "Design review feedback: Great progress on the new user onboarding flow. Left a few comments on the Figma mockup regarding button spacing.",
        "Customer support ticket #8912: Customer confirmed the issue was resolved by clearing browser cache. Closing ticket as resolved.",
        "Happy Friday: Reminder that our office will be closed on Monday for the bank holiday. Have a wonderful long weekend everyone!",
        "Conference schedule: Here is the finalized speaker lineup and workshop schedule for next month's cybersecurity symposium.",
        
        # Routine Notifications & Receipts
        "Your GitHub receipt for September 2026: Thank you for your payment of $21.00 for GitHub Team subscription. View receipt in billing settings.",
        "Package delivered: Your Amazon package with order #112-98471 was delivered to your front porch today at 2:15 PM.",
        "Calendar invite accepted: John accepted your invitation to 'Architecture Discussion' scheduled for Wednesday 3:00 PM.",
        "New comment on Jira ticket ENG-104: Sara updated the task status from In Progress to Done.",
        "Flight itinerary confirmation: Your upcoming flight from New York to San Francisco is confirmed. Seat 14A selected.",
        "Hotel reservation confirmation: Your booking at Marriott Hotel is confirmed for check-in on October 5th.",
        "Python Software Foundation Newsletter: What's new in Python 3.14, upcoming PyCon dates, and community grants.",
        "Spotify monthly summary: Here are your top played artists and podcasts for the month of August.",
        "Substack Digest: Here are the top technical articles published this week by writers you follow.",
    ]

    # Augment samples with variations to balance and enlarge dataset
    texts: List[str] = []
    labels: List[int] = []

    for item in phishing:
        texts.append(item)
        labels.append(1)
        # Variation with additional urgency prefix
        texts.append(f"URGENT ATTENTION: {item}")
        labels.append(1)

    for item in benign:
        texts.append(item)
        labels.append(0)
        # Variation with informal greeting
        texts.append(f"Hi team, just checking in. {item}")
        labels.append(0)

    return texts, labels


def load_csv_dataset(csv_path: str, text_col: str = "text", label_col: str = "label") -> Tuple[List[str], List[int]]:
    """Load an external CSV dataset containing text and binary label columns."""
    texts: List[str] = []
    labels: List[int] = []

    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if text_col in row and label_col in row:
                t = row[text_col].strip()
                try:
                    l = int(row[label_col])
                    if t and l in [0, 1]:
                        texts.append(t)
                        labels.append(l)
                except ValueError:
                    continue

    return texts, labels
