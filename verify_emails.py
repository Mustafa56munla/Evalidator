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
from concurrent.futures import ThreadPoolExecutor, as_completed

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


def smtp_check(email, from_addr, password):
    """Performs the final SMTP check to see if a user exists."""
    time.sleep(random.uniform(0.5, 1.5))  # Add a polite delay
    try:
        domain = email.split('@')[1]
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_host = str(mx_records[0].exchange).rstrip('.')
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10)
        server.starttls()
        server.login(from_addr, password)
        server.mail(from_addr)
        code, _ = server.rcpt(email)
        server.quit()
        return code == 250
    except (smtplib.SMTPException, socket.timeout, ConnectionRefusedError) as e:
        print(f"SMTP check failed for {email}: {type(e).__name__}")
        return None


# -----------------------
# Analyzer
# -----------------------
def analyze_email(email, from_addr, password, cache):
    """Analyzes a single email by running it through a funnel of checks."""
    result = {
        "email": email, "syntax_valid": False, "mx_valid": False,
        "is_disposable": False, "is_catch_all": False, "smtp_valid": None,
        "status": "Unprocessed", "send": "Don't Send", "tested_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    if not is_valid_syntax(email):
        result["status"] = "Invalid Syntax"
        return result
    result["syntax_valid"] = True

    domain = email.split('@')[1].lower()

    if domain in DISPOSABLE_DOMAINS:
        result["is_disposable"] = True
        result["status"] = "Disposable"
        return result

    # --- Use the cache for domain-level checks ---
    if domain in cache:
        domain_info = cache[domain]
        result.update(domain_info)
    else:
        mx_ok = domain_has_mail_server(domain)
        result["mx_valid"] = mx_ok

        catch_all = is_catch_all(domain, from_addr, password) if mx_ok else False
        result["is_catch_all"] = catch_all

        # Save results to cache
        cache[domain] = {"mx_valid": mx_ok, "is_catch_all": catch_all}
    # --- End cache logic ---

    if not result["mx_valid"]:
        result["status"] = "No Mail Server (MX/A Record)"
        return result

    if result["is_catch_all"]:
        result["status"] = "Catch-all"
        result["send"] = "Send with caution"
        return result

    # Perform final SMTP check only if necessary
    smtp_ok = smtp_check(email, from_addr, password)
    result["smtp_valid"] = smtp_ok

    if smtp_ok is True:
        result["status"] = "Valid"
        result["send"] = "Send"
    elif smtp_ok is False:
        result["status"] = "Invalid (Rejected by SMTP)"
    else:
        result["status"] = "Unverifiable (SMTP Error)"

    print(f"Processed: {email:<40} -> Status: {result['status']}")
    return result


# -----------------------
# Main Execution
# -----------------------
def main():
    try:
        df = pd.read_csv("emails.csv")
        if 'email' not in df.columns:
            print("Error: CSV must have a column named 'email'.")
            return
        email_list = df['email'].dropna().unique().tolist()
    except FileNotFoundError:
        print("Error: emails.csv not found.")
        return

    results = []
    domain_cache = {}

    print(f"\n🔍 Verifying {len(email_list)} unique emails...\n")

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(analyze_email, email, FROM_EMAIL, PASSWORD, domain_cache): email for email in
                   email_list}

        for future in as_completed(futures):
            results.append(future.result())

    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    output_file = f"verified_results_{timestamp}.csv"
    pd.DataFrame(results).to_csv(output_file, index=False)
    print(f"\n🎉 Verification complete. Results saved to: {output_file}")


if __name__ == "__main__":

    main()
