# verify_emails.py

import os
import re
import smtplib
import socket
import random
import string
import time
from datetime import datetime

import pandas as pd
import requests
import dns.resolver
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv

# -----------------------
# Configuration Loading
# -----------------------
load_dotenv()
FROM_EMAIL = os.getenv("FROM_EMAIL")
PASSWORD = os.getenv("EMAIL_PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.hostinger.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))

if not all([FROM_EMAIL, PASSWORD]):
    raise ValueError("FROM_EMAIL and EMAIL_PASSWORD must be set in your .env file.")


# -----------------------
# Disposable Domains
# -----------------------
def get_disposable_domains():
    """Fetches a list of disposable domains from a trusted source."""
    url = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        domains = set(response.text.splitlines())
        print(f"✅ Loaded {len(domains)} disposable domains.")
        return domains
    except requests.RequestException as e:
        print(f"⚠️ Could not fetch disposable domains list: {e}. Using a small fallback list.")
        return {"mailinator.com", "10minutemail.com", "guerrillamail.com"}


DISPOSABLE_DOMAINS = get_disposable_domains()


# -----------------------
# Core Check Functions
# -----------------------
def is_valid_syntax(email):
    """Validates email syntax using the email-validator library."""
    try:
        validate_email(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False


def domain_has_mail_server(domain):
    """Checks for MX records, with a fallback to A records."""
    try:
        dns.resolver.resolve(domain, 'MX')
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        try:
            dns.resolver.resolve(domain, 'A')
            return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            return False
    except dns.resolver.Timeout:
        return False


def smtp_check(email, from_addr):
    """
    Performs an SMTP check by connecting to the recipient's MX server on port 25.
    This version does not log in, simulating a standard server-to-server mail transfer.
    """
    time.sleep(random.uniform(0.5, 1.5)) # Add a polite delay
    try:
        domain = email.split('@')[1]
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_host = str(mx_records[0].exchange).rstrip('.')

        # Connect on port 25, the standard for MTA-to-MTA communication
        with smtplib.SMTP(host=mx_host, port=25, timeout=10) as server:
            server.helo() # Use HELO for unauthenticated check
            server.mail(from_addr)
            code, _ = server.rcpt(email)
            
            # Note: A 250 code means the user is valid or the server is a catch-all.
            # A code in the 500s means the user is definitively invalid.
            return code == 250

    except (smtplib.SMTPException, socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"SMTP check failed for {email}: {type(e).__name__}")
        return None # Indicate the check could not be completed


# -----------------------
# Analyzer
# -----------------------
def analyze_email(email, from_addr, password, cache):
    """Analyzes a single email using a more accurate two-step SMTP check."""
    result = {
        "email": email, "syntax_valid": False, "mx_valid": False,
        "is_disposable": False, "is_catch_all": False, "smtp_valid": None,
        "status": "Unprocessed", "send": "Don't Send", "tested_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    # --- Step 1: Basic Checks (Syntax, Disposable) ---
    if not is_valid_syntax(email):
        result["status"] = "Invalid Syntax"
        return result
    result["syntax_valid"] = True

    domain = email.split('@')[1].lower()

    if domain in DISPOSABLE_DOMAINS:
        result["is_disposable"] = True
        result["status"] = "Disposable"
        return result

    # --- Step 2: Domain & MX Record Check (with Cache) ---
    if domain in cache:
        result["mx_valid"] = cache[domain]["mx_valid"]
    else:
        mx_ok = domain_has_mail_server(domain)
        result["mx_valid"] = mx_ok
        cache[domain] = {"mx_valid": mx_ok}

    if not result["mx_valid"]:
        result["status"] = "No Mail Server (MX/A Record)"
        return result

    # --- Step 3: Advanced Two-Step SMTP Verification ---
    user_check_result = smtp_check(email, from_addr, password)
    
    if user_check_result is False:
        # The server explicitly rejected the user. This is a definitive "Invalid".
        result["smtp_valid"] = False
        result["status"] = "Invalid (Rejected by SMTP)"

    elif user_check_result is None:
        # The check failed due to a network error or timeout.
        result["status"] = "Unverifiable (SMTP Error)"

    elif user_check_result is True:
        # The server accepted the user, but we must check if it's a catch-all.
        # We perform a second check with a bogus email address.
        bogus_user = ''.join(random.choices(string.ascii_lowercase + string.digits, k=15))
        bogus_email = f"{bogus_user}@{domain}"
        bogus_check_result = smtp_check(bogus_email, from_addr, password)

        if bogus_check_result is True:
            # Server accepted the real AND the bogus email -> CATCH-ALL
            result["is_catch_all"] = True
            result["status"] = "Catch-all"
            result["send"] = "Send with caution"
        elif bogus_check_result is False:
            # Server accepted the real but rejected the bogus email -> VALID
            result["smtp_valid"] = True
            result["status"] = "Valid"
            result["send"] = "Send"
        else:
            # Bogus check had an error, so the result is uncertain.
            result["status"] = "Unverifiable (SMTP Error during catch-all check)"

    print(f"Processed: {email:<40} -> Status: {result['status']}")
    return result

