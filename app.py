import streamlit as st
import pandas as pd
import os
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Import the core functions from your original script
from verify_emails import (
    get_disposable_domains,
    analyze_email
)

# --- App Configuration & Secrets ---
st.set_page_config(page_title="Email Validator", layout="centered")

# Load secrets: Works locally with .env and on Streamlit Cloud with st.secrets
try:
    # Try to load from Streamlit's secrets manager first
    FROM_EMAIL = st.secrets["FROM_EMAIL"]
    PASSWORD = st.secrets["EMAIL_PASSWORD"]
    st.info("Credentials loaded from Streamlit Secrets.")
except FileNotFoundError:
    # Fallback to .env for local development
    load_dotenv()
    FROM_EMAIL = os.getenv("FROM_EMAIL")
    PASSWORD = os.getenv("EMAIL_PASSWORD")
    st.info("Credentials loaded from local .env file.")

if not all([FROM_EMAIL, PASSWORD]):
    st.error("FATAL: Email credentials are not configured. App cannot run.")
    st.stop()

# --- Main App UI ---
st.title("📧 Email Verification Tool")
st.write(
    "Upload a CSV file with a column named 'email'. The script will verify each email and provide a downloadable results file.")

# Pre-load disposable domains once
with st.spinner("Loading disposable domain list..."):
    DISPOSABLE_DOMAINS = get_disposable_domains()

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
            domain_cache = {}

            progress_bar = st.progress(0)
            status_text = st.empty()

            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {executor.submit(analyze_email, email, FROM_EMAIL, PASSWORD, domain_cache): email for email in
                           email_list}

                for i, future in enumerate(as_completed(futures)):
                    results.append(future.result())
                    progress = (i + 1) / len(email_list)
                    progress_bar.progress(progress)
                    status_text.text(f"Processing... {i + 1}/{len(email_list)}")

            st.success("✅ Verification Complete!")
            status_text.text("")

            results_df = pd.DataFrame(results)
            csv_output = results_df.to_csv(index=False).encode('utf-8')

            st.download_button(
                label="📥 Download Results",
                data=csv_output,
                file_name=f"verified_{uploaded_file.name}",
                mime="text/csv",
            )
            st.dataframe(results_df)