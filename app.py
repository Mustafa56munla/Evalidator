# app.py

import streamlit as st
import pandas as pd
import os
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import the core functions from your logic script
from verify_emails import (
    get_disposable_domains,
    analyze_email
)

# --- App Configuration & Secrets ---
st.set_page_config(page_title="Email Validator", layout="centered")

# Load secrets: Works locally with .env and on Streamlit Cloud with st.secrets
try:
    FROM_EMAIL = st.secrets["FROM_EMAIL"]
except (FileNotFoundError, KeyError):
    load_dotenv()
    FROM_EMAIL = os.getenv("FROM_EMAIL")

if not FROM_EMAIL:
    st.error("FATAL: FROM_EMAIL is not configured. Add it to your .env file or Streamlit Secrets.")
    st.stop()

# --- Reusable Data & Cache ---
@st.cache_resource
def load_disposable_list():
    """Loads the disposable domain list and caches it."""
    return get_disposable_domains()

DISPOSABLE_DOMAINS = load_disposable_list()
domain_cache = {} # A simple in-memory cache for the session

# --- Main App UI ---
st.title("📧 Email Verification Tool")

# --- Single Email Verification ---
st.subheader("Verify a Single Email")
single_email = st.text_input("Enter one email address to verify:", placeholder="example@domain.com")

if st.button("Verify Email"):
    if single_email:
        with st.spinner(f"Verifying {single_email}..."):
            result = analyze_email(single_email, FROM_EMAIL, domain_cache)
        
        status = result.get("status", "Unknown")
        send_decision = result.get("send", "Don't Send")

        if status == "Valid":
            st.success(f"**Status: {status}** ({send_decision})")
        elif status in ["Catch-all", "Unverifiable (SMTP Error)"]:
            st.warning(f"**Status: {status}** ({send_decision})")
        else:
            st.error(f"**Status: {status}** ({send_decision})")
        
        with st.expander("Show full details"):
            st.json(result)
    else:
        st.warning("Please enter an email address in the box.")

# --- CSV File Verification ---
st.subheader("Or, Verify a Full CSV File")

# NEW: Add instructions for the CSV format
with st.info("Your CSV file must contain a single column with the header name `email`.", icon="ℹ️"):
    st.write("Example:")
    st.code("""
email
example1@domain.com
example2@another.com
example3@business.org
    """)
    

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
                futures = {executor.submit(analyze_email, email, FROM_EMAIL, domain_cache): email for email in email_list}
                
                for i, future in enumerate(as_completed(futures)):
                    results.append(future.result())
                    progress = (i + 1) / len(email_list)
                    progress_bar.progress(progress, text=f"Processing... {i+1}/{len(email_list)}")

            st.success("✅ Verification Complete!")
            
            results_df = pd.DataFrame(results)
            csv_output = results_df.to_csv(index=False).encode('utf-8')
            
            st.download_button(
               label="📥 Download Results",
               data=csv_output,
               file_name=f"verified_{uploaded_file.name}",
               mime="text/csv",
            )
            st.dataframe(results_df)

