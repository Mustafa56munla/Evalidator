# app.py

import streamlit as st
import pandas as pd
import time
from verify_emails import get_disposable_domains, analyze_email, verify_with_mailbite_api

st.set_page_config(page_title="Email Validator", layout="centered")

# Load secrets
try:
    FROM_EMAIL = st.secrets["FROM_EMAIL"]
    PASSWORD = st.secrets["EMAIL_PASSWORD"]
    APP_PASSWORD = st.secrets["APP_PASSWORD"]
    MAILBITE_API_KEYS_STR = st.secrets.get("MAILBITE_API_KEYS", "")
except (FileNotFoundError, KeyError):
    st.error("FATAL: Required secrets are not set in Streamlit Cloud.")
    st.stop()

# Password protection
def check_password():
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

# Load disposable email list
@st.cache_resource
def load_disposable_list():
    return get_disposable_domains()

DISPOSABLE_DOMAINS = load_disposable_list()

# Full email verification function with progress
def run_full_verification(email_list, api_keys_str, progress_callback=None):
    domain_cache = {}
    results = []
    total = len(email_list)
    for i, email in enumerate(email_list, start=1):
        result = analyze_email(email, FROM_EMAIL, PASSWORD, domain_cache)
        results.append(result)
        if progress_callback:
            progress_callback(i, total, result)
        time.sleep(0.05)  # brief delay for UI responsiveness

    # Optional: API fallback for catch-all
    catch_all_results = [res for res in results if res['status'] == 'Catch-all']
    api_keys = api_keys_str.split(',') if api_keys_str else []
    if catch_all_results and api_keys:
        available_keys = list(api_keys)
        for res in results:
            if res['status'] == 'Catch-all':
                if not available_keys:
                    res['status'] = "API Keys Exhausted"
                    continue
                current_key = available_keys[0]
                api_result = verify_with_mailbite_api(res['email'], current_key)
                if api_result.get("key_exhausted"):
                    available_keys.pop(0)
                    if available_keys:
                        api_result = verify_with_mailbite_api(res['email'], available_keys[0])
                    else:
                        res['status'] = "API Keys Exhausted"
                        continue
                res['status'] = api_result["status"]
                if "Valid" in res['status']:
                    res['send'] = "Send"
                elif "Invalid" in res['status']:
                    res['send'] = "Don't Send"
    return results

# UI layout
st.title("🚀Az Evalidator🚀")
with st.expander("How this tool works"):
    st.write("""
        This tool performs a two-stage verification:
        1.  **Initial Check:** A fast, local check filters out invalid, disposable, and easily verifiable emails.
        2.  **API Check:** Any emails marked as "Catch-all" are automatically re-verified using API in a better IP Reputation for higher accuracy.
    """)

st.subheader("Verify a CSV File")
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

        if st.button(f"🚀 Start Full Verification for {len(email_list)} Emails"):
            progress_bar = st.progress(0)
            status_text = st.empty()
            preview_box = st.empty()
            results_preview = []

            def update_progress(count, total, result):
                percent = int(count / total * 100)
                progress_bar.progress(percent)
                status_text.info(f"Verifying: {result['email']} ({count}/{total}) → {result['status']}")
                if count % 10 == 0 or count == total:
                    preview_box.dataframe(pd.DataFrame(results_preview[-10:]))
                results_preview.append(result)

            with st.spinner("Performing verification... This may take several minutes."):
                final_results = run_full_verification(email_list, MAILBITE_API_KEYS_STR, progress_callback=update_progress)

            st.success("✅ Verification Complete!")
            results_df = pd.DataFrame(final_results)
            csv_output = results_df.to_csv(index=False).encode('utf-8')
            st.download_button(label="📥 Download Final Results", data=csv_output, file_name=f"verified_{uploaded_file.name}", mime="text/csv")
            st.dataframe(results_df)
