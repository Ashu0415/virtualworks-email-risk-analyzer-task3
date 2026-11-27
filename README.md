# Email Risk Analyzer

A Python security analysis tool developed as part of the **VirtualWorks Cyber Security Internship** (`task3`). This program inspects email subjects and body content for common phishing and social engineering indicators, assigning an overall risk rating to help users identify malicious messages.

## Features
- **Social Engineering Detection:** Scans text for high-pressure urgency phrases and common phishing lures.
- **URL & Link Inspection:** Flags embedded links, unencrypted `http://` URLs, and suspicious raw IP-address links.
- **Credential & Attachment Checks:** Detects requests for sensitive data (passwords, OTPs, banking info) and mentions of risky executable/archive extensions.
- **Risk Scoring System:** Categorizes emails into *Low Risk*, *Moderate Risk*, or *High Risk* with a detailed breakdown of triggered alerts.

## Prerequisites
- Python 3.x (uses only the built-in `re` module; no external packages required).

## How to Run
1. Clone the repository:
   ```bash
   git clone [https://github.com/](https://github.com/)<your-username>/virtualworks-email-risk-analyzer.git
   cd virtualworks-email-risk-analyzer
