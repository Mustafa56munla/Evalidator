# verify_emails.py

import os
import re
import smtplib
import socket
import random
import string
import time
from datetime import datetime
import requests
import dns.resolver
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv

load_dotenv()
FROM_EMAIL = os.getenv("FROM_EMAIL")
PASSWORD = os.getenv("EMAIL_PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.hostinger.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))

KNOWN_MAJOR_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", 
    "yahoo.com", "aol.com", "icloud.com", "protonmail.com", "zoho.com"
}

def get_disposable_domains():
    url = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return set(response.text.splitlines())
    except requests.RequestException:
        return {"mailinator.com", "10minutemail.com"}

DISPOSABLE_DOMAINS = get_disposable_domains()

def is_valid_syntax(email):
    try:
        validate_email(email, check_deliverability=False); return True
    except EmailNotValidError:
        return False

def domain_has_mail_server(domain):
    try:
        dns.resolver.resolve(domain, 'MX'); return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        try:
            dns.resolver.resolve(domain, 'A'); return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            return False

def smtp_check(email, from_addr, password):
    time.sleep(random.uniform(0.5, 1.5))
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(from_addr, password)
            server.mail(from_addr)
            code, _ = server.rcpt(email)
            return code == 250
    except (smtplib.SMTPException, socket.timeout, ConnectionRefusedError, OSError):
        return None

def analyze_email(email, from_addr, password, cache):
    result = {
        "email": email, "syntax_valid": False, "mx_valid": False,
        "is_disposable": False, "is_catch_all": False, "smtp_valid": None,
        "status": "Unprocessed", "send": "Don't Send", "tested_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    if not is_valid_syntax(email):
        result["status"] = "Invalid Syntax"; return result
    result["syntax_valid"] = True
    domain = email.split('@')[1].lower()
    if domain in DISPOSABLE_DOMAINS:
        result["is_disposable"] = True; result["status"] = "Disposable"; return result
    if domain in cache:
        result["mx_valid"] = cache.get(domain, {}).get("mx_valid", False)
    else:
        mx_ok = domain_has_mail_server(domain); result["mx_valid"] = mx_ok
        cache[domain] = {"mx_valid": mx_ok}
    if not result["mx_valid"]:
        result["status"] = "No Mail Server (MX/A Record)"; return result
    user_check_result = smtp_check(email, from_addr, password)
    if user_check_result is False:
        result["smtp_valid"] = False; result["status"] = "Invalid (Rejected by SMTP)"
    elif user_check_result is None:
        result["status"] = "Unverifiable (SMTP Error)"
    elif user_check_result is True:
        bogus_user = ''.join(random.choices(string.ascii_lowercase + string.digits, k=15))
        bogus_email = f"{bogus_user}@{domain}"
        bogus_check_result = smtp_check(bogus_email, from_addr, password)
        if bogus_check_result is True:
            result["is_catch_all"] = True; result["status"] = "Catch-all"; result["send"] = "Send with caution"
        elif bogus_check_result is False:
            result["smtp_valid"] = True; result["status"] = "Valid"; result["send"] = "Send"
        else:
            result["status"] = "Unverifiable (SMTP Error during catch-all check)"
    if result["status"] == "Catch-all" and domain in KNOWN_MAJOR_PROVIDERS:
        result["status"] = "Acceptable (Major Provider)"; result["send"] = "Send"
        result["is_catch_all"] = False
    return result

def verify_with_mailbite_api(email, api_key):
    api_url = f"https://api.mailbite.io/v1/verify?email={email}&apikey={api_key}"
    try:
        response = requests.get(api_url, timeout=20)
        api_result = response.json()
        if response.status_code != 200 and "credits" in api_result.get("error", "").lower():
            return {"status": "API Key Limit Reached", "key_exhausted": True}
        response.raise_for_status()
        status_str = "Unverifiable (API)"
        if api_result.get("status") == "deliverable":
            status_str = "Valid (API Verified)"
        elif api_result.get("status") == "undeliverable":
            status_str = "Invalid (API Verified)"
        elif api_result.get("is_catchall"):
            status_str = "Catch-all (API Verified)"
        return {"status": status_str, "key_exhausted": False}
    except requests.RequestException:
        return {"status": "API Error", "key_exhausted": False}
