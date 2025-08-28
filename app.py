# app.py

import streamlit as st
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import the core functions from your logic script
from verify_emails import get_disposable_domains, analyze_email

# --- App Configuration & Secrets ---
st.set_page_config(page_title="Email Validator", layout="centered")

# Load credentials and passwords from Streamlit Secrets
try:
    FROM_EMAIL = st.secrets["FROM_EMAIL"]
    PASSWORD = st.secrets["EMAIL_PASSWORD"]
    APP_PASSWORD = st.secrets["APP_PASSWORD"]
except (FileNotFoundError, KeyError):
    st.error("FATAL: Required secrets (FROM_EMAIL, EMAIL_PASSWORD, APP_PASSWORD) are not set in Streamlit Cloud.")
    st.stop()
    
# --- Password Protection ---
def check_password():
    """Returns `True` if the user had the correct password."""
    if "password_correct" not in st.session_state:
        st.session_state["password_correct"] = False

    if st.session_state["password_correct"]:
        return True

    password = st.text_input("Enter a password to access the tool", type="password")
    if st.button("Login"):
        if password == APP_PASSWORD:
            st.session_state["password_correct"] = True
            st.rerun()
        else:
            st.error("The password you entered is incorrect.")
    return False

if not check_password():
    st.stop()

# --- Reusable Data & Cache ---
@st.cache_resource
def load_disposable_list():
    """Loads the disposable domain list and caches it."""
    return get_disposable_domains()

DISPOSABLE_DOMAINS = load_disposable_list()
domain_cache = {}

# --- Main App UI ---
st.title("📧 Email Verification Tool")

# --- Single Email Verification ---
st.subheader("Verify a Single Email")
single_email = st.text_input("Enter one email address to verify:", placeholder="example@domain.com")

if st.button("Verify Email"):
    if single_email:
        with st.spinner(f"Verifying {single_email}..."):
            result = analyze_email(single_email, FROM_EMAIL, PASSWORD, domain_cache)
        
        status = result.get("status", "Unknown")
        if status == "Valid":
            st.success(f"**Status: {status}** ({result.get('send', 'N/A')})")
        elif "Unverifiable" in status or "Catch-all" in status:
            st.warning(f"**Status: {status}** ({result.get('send', 'N/A')})")
        else:
            st.error(f"**Status: {status}** ({result.get('send', 'N/A')})")
        
        with st.expander("Show full details"):
            st.json(result)
    else:
        st.warning("Please enter an email address in the box.")

# --- CSV File Verification ---
st.subheader("Or, Verify a Full CSV File")
with st.info("Your CSV file must contain a column with the header name `email`.", icon="ℹ️"):
    st.code("email\nexample1@domain.com\nexample2@another.com")
    
uploaded_file = st.file_uploader("Choose a CSV file", type="csv")

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    if 'email' not in df.columns:
        st.error("Error: Your CSV must have a column named 'email'.")
    else:
        email_list = df['email'].dropna().unique().tolist()
        st.success(f"File uploaded successfully! Found {len(email_list)} unique emails.")

        if st.button(f"🚀 Start Verification for {len(email_list)} Emails"):
            results = []
            progress_bar = st.progress(0, text="Starting verification...")
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {executor.submit(analyze_email, email, FROM_EMAIL, PASSWORD, domain_cache): email for email in email_list}
                for i, future in enumerate(as_completed(futures)):
                    results.append(future.result())
                    progress_bar.progress((i + 1) / len(email_list), text=f"Processing... {i+1}/{len(email_list)}")
            st.success("✅ Verification Complete!")
            results_df = pd.DataFrame(results)
            csv_output = results_df.to_csv(index=False).encode('utf-8')
            st.download_button(label="📥 Download Results", data=csv_output, file_name=f"verified_{uploaded_file.name}", mime="text/csv")
            st.dataframe(results_df)
