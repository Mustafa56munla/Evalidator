# app.py

import streamlit as st
import pandas as pd
from concurrent.futures import ThreadPoolExecutor

from verify_emails import get_disposable_domains, analyze_email, verify_with_mailbite_api

st.set_page_config(page_title="Email Validator", layout="centered")

try:
    FROM_EMAIL = st.secrets["FROM_EMAIL"]
    PASSWORD = st.secrets["EMAIL_PASSWORD"]
    APP_PASSWORD = st.secrets["APP_PASSWORD"]
    MAILBITE_API_KEYS_STR = st.secrets.get("MAILBITE_API_KEYS", "")
except (FileNotFoundError, KeyError):
    st.error("FATAL: Required secrets are not set in Streamlit Cloud.")
    st.stop()
    
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

@st.cache_resource
def load_disposable_list():
    return get_disposable_domains()

DISPOSABLE_DOMAINS = load_disposable_list()

def run_full_verification(email_list, api_keys_str):
    domain_cache = {}
    with ThreadPoolExecutor(max_workers=4) as executor:
        initial_results = list(executor.map(lambda email: analyze_email(email, FROM_EMAIL, PASSWORD, domain_cache), email_list))
    catch_all_results = [res for res in initial_results if res['status'] == 'Catch-all']
    api_keys = api_keys_str.split(',') if api_keys_str else []
    if catch_all_results and api_keys:
        available_keys = list(api_keys)
        for result_item in initial_results:
            if result_item['status'] == 'Catch-all':
                if not available_keys:
                    result_item['status'] = "API Keys Exhausted"; continue
                current_key = available_keys[0]
                api_result = verify_with_mailbite_api(result_item['email'], current_key)
                if api_result.get("key_exhausted"):
                    available_keys.pop(0)
                    if available_keys:
                        api_result = verify_with_mailbite_api(result_item['email'], available_keys[0])
                    else:
                        result_item['status'] = "API Keys Exhausted"; continue
                result_item['status'] = api_result["status"]
                if "Valid" in result_item['status']: result_item['send'] = "Send"
                elif "Invalid" in result_item['status']: result_item['send'] = "Don't Send"
    return initial_results

st.title("Az Evalidator")
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
            with st.spinner("Performing verification... This may take several minutes."):
                final_results = run_full_verification(email_list, MAILBITE_API_KEYS_STR)
            st.success("✅ Verification Complete!")
            results_df = pd.DataFrame(final_results)
            csv_output = results_df.to_csv(index=False).encode('utf-8')
            st.download_button(label="📥 Download Final Results", data=csv_output, file_name=f"verified_{uploaded_file.name}", mime="text/csv")
            st.dataframe(results_df)

