import streamlit as st
import pandas as pd
import joblib
import json
import os
import shap
import matplotlib.pyplot as plt
import numpy as np
import re
import requests
import hashlib

from extractor import extract_features

# --- CONFIGURATION ---
VT_API_KEY = "fe62a39bb172f6a5554da434b689cbd672f6a795ab8abcf56d940e7eacfdfc7e"

# --- PAGE CONFIG ---
st.set_page_config(page_title="GlassBox AI Antivirus", page_icon="🛡️", layout="wide")


# --- HELPER FUNCTIONS ---

def interpret_feature(feature_name, value, impact_score):
    """Returns human-readable explanation for specific feature values."""
    is_risk = impact_score > 0
    if "E_" in feature_name or "Entropy" in feature_name:
        if value > 7.0 and is_risk:
            return "High Entropy (>7.0). Indicates compressed or encrypted code (Packing)."
        elif value < 6.0 and not is_risk:
            return "Normal Entropy. Consistent with standard, unhidden code."
    if feature_name == "filesize":
        if value < 20000 and is_risk:
            return "Suspiciously small file size (<20KB)."
        elif value > 1000000 and not is_risk:
            return "Large file size (>1MB). Malware is usually smaller."
    if feature_name == "CheckSum":
        if value == 0 and is_risk:
            return "Zero Checksum. Often implies lazy/malicious compilation."
        elif value > 0 and not is_risk:
            return "Valid Checksum present."
    if is_risk: return "Value is statistically associated with Malware."
    return "Value is statistically associated with Safe software."


def analyze_strings(file_path, min_length=4):
    """
    Extracts ASCII strings and filters them for 'Indicators of Compromise' (IOCs).
    Returns: (list of all strings, dict of flagged artifacts)
    """
    with open(file_path, 'rb') as f:
        data = f.read()

    # 1. Extract all printable strings
    chars = re.findall(b'[ -~]{4,}', data)
    all_strings = [c.decode('utf-8') for c in chars]

    # 2. Filter for specific IOCs using Regex
    flagged = {
        "IP Addresses": [],
        "URLs": [],
        "Suspicious Keywords": [],
        "Registry/File Paths": []
    }

    # Regex Patterns
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    sus_keywords = ["cmd.exe", "powershell", "wscript", "cscript", "system32", "tor", "bitcoin", "wallet", "keylog"]
    path_pattern = re.compile(r'[C-Z]:\\[a-zA-Z0-9_\\]+|HKEY_')

    for s in all_strings:
        if ip_pattern.search(s):
            flagged["IP Addresses"].append(s)
        if url_pattern.search(s):
            flagged["URLs"].append(s)
        if path_pattern.search(s):
            flagged["Registry/File Paths"].append(s)
        # Check keywords (case insensitive)
        for kw in sus_keywords:
            if kw in s.lower():
                flagged["Suspicious Keywords"].append(s)

    return all_strings, flagged


def plot_entropy_bitmap(file_path):
    """Visualizes the file as a 2D square image."""
    with open(file_path, 'rb') as f:
        byte_data = list(f.read())

    file_size = len(byte_data)
    width = int(np.ceil(np.sqrt(file_size)))
    padding = (width * width) - file_size
    byte_data += [0] * padding
    img_data = np.reshape(byte_data, (width, width))

    fig, ax = plt.subplots(figsize=(4, 4))
    ax.imshow(img_data, cmap='inferno', interpolation='nearest')
    ax.axis('off')
    return fig


def check_virustotal(file_path, api_key):
    """Checks the file hash against VirusTotal DB."""
    if not api_key: return None
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    file_hash = hash_md5.hexdigest()

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()['data']['attributes']['last_analysis_stats']
        elif response.status_code == 404:
            return "Not Found"
    except:
        return None
    return None


# --- LOAD RESOURCES ---
@st.cache_resource
def load_system():
    model = joblib.load("model/model.pkl")
    with open("features/features.json", "r") as f:
        feature_names = json.load(f)
    return model, feature_names


try:
    model, feature_names = load_system()
except Exception as e:
    st.error(f"❌ System Error: {e}")
    st.stop()

# --- MAIN APP LAYOUT ---
st.title("🛡️ GlassBox Malware Detector v2.1")
st.markdown("### Explainable AI & Forensic Analysis Engine")

uploaded_file = st.file_uploader("Upload PE File (.exe)", type=["exe", "dll"])

if uploaded_file:
    temp_filename = "temp_scan_file.exe"
    with open(temp_filename, "wb") as f:
        f.write(uploaded_file.getbuffer())

    with st.spinner("⚡ Running Deep Scan (Static + Heuristic + Visual)..."):
        # 1. CORE AI SCAN
        feature_vector = extract_features(temp_filename)

        if feature_vector:
            df = pd.DataFrame([feature_vector], columns=feature_names)
            prediction = model.predict(df)[0]
            probability = model.predict_proba(df)[0][1] # defaults to 50%

            # Set threshold to 35% instead of 50%
            if probability > 0.35:
                prediction = 1
            else:
                prediction = 0

            # 2. RUN EXTRA FORENSICS
            all_strings, flagged_artifacts = analyze_strings(temp_filename)
            vt_stats = check_virustotal(temp_filename, VT_API_KEY)

            # --- HYBRID DECISION LOGIC ---
            # 1. Default to AI Opinion
            final_verdict = prediction
            final_probability = probability
            verdict_text = "MALICIOUS"
            verdict_color = "error"  # Red

            # 2. Check VirusTotal (The Veto Power)
            vt_score = 0
            if isinstance(vt_stats, dict):
                vt_score = vt_stats.get('malicious', 0)

            # SCENARIO A: AI says Malware, but VirusTotal says Clean (False Positive)
            if prediction == 1 and vt_score == 0:
                final_verdict = 0  # Override to Safe
                verdict_text = "BENIGN (Verified by Threat Intel)"
                verdict_color = "success"  # Green
                st.toast("🛡️ AI False Positive detected. Overridden by VirusTotal.", icon="✅")

            # SCENARIO B: AI says Safe, but VirusTotal says Malware (False Negative)
            if prediction == 0 and vt_score >= 3:
                final_verdict = 1  # Override to Malware
                verdict_text = "MALICIOUS (Flagged by Threat Intel)"
                verdict_color = "error"
                st.toast("⚠️ AI False Negative detected. Overridden by VirusTotal.", icon="🚨")

            # --- DASHBOARD UI ---
            st.divider()

            # --- DASHBOARD ---
            st.divider()

            # A. VERDICT BANNER (Logic Upgrade)
            col_v1, col_v2 = st.columns([2, 1])

            # 1. Calculate VirusTotal Score
            vt_score = 0
            if isinstance(vt_stats, dict):
                vt_score = vt_stats.get('malicious', 0)

            with col_v1:
                # --- SCENARIO 1: FALSE POSITIVE (Yellow) ---
                # AI says Malware (1), but VirusTotal says Clean (0)
                if prediction == 1 and vt_score == 0:
                    st.warning("⚠️ VERDICT: SUSPICIOUS (Likely False Positive)")
                    st.markdown(f"**AI Confidence:** {probability * 100:.2f}% (High Risk Structure)")
                    st.caption(
                        "Result: The AI detected suspicious anomalies (e.g., Packing), but VirusTotal reports the file is clean. This is likely a False Positive due to the file's structure.")

                # --- SCENARIO 2: MALWARE (Red) ---
                # AI says Malware OR VirusTotal says Malware (>2 flags)
                elif prediction == 1 or vt_score > 2:
                    st.error("🚨 VERDICT: MALICIOUS")
                    if prediction == 1:
                        st.markdown(f"**AI Confidence:** {probability * 100:.2f}%")
                    else:
                        st.markdown(f"**AI Confidence:** {(1 - probability) * 100:.2f}% (Overridden by VT)")

                # --- SCENARIO 3: SAFE (Green) ---
                else:
                    st.success("✅ VERDICT: BENIGN")
                    st.markdown(f"**AI Safety Score:** {(1 - probability) * 100:.2f}%")

            with col_v2:
                # VirusTotal Badge (Kept the same)
                if vt_stats == "Not Found":
                    st.warning("⚠️ Unknown to VirusTotal")
                elif isinstance(vt_stats, dict):
                    if vt_score > 0:
                        st.metric("VirusTotal", f"{vt_score} Flags", "Malicious", delta_color="inverse")
                    else:
                        st.metric("VirusTotal", "Clean", "Verified")
                else:
                    st.caption("VirusTotal: Skipped")
            # B. TABBED ANALYSIS
            tab1, tab2, tab3 = st.tabs(["🔬 AI Explainability", "🖼️ Visual Forensics", "🕵️ String Heuristics"])

            with tab1:
                st.subheader("Why did the AI make this decision?")
                explainer = shap.TreeExplainer(model)
                shap_values = explainer(df)
                fig, ax = plt.subplots(figsize=(8, 3))
                shap.plots.waterfall(shap_values[0], max_display=7, show=False)
                st.pyplot(fig, clear_figure=True)

                st.markdown("**Top Influential Factors:**")
                feature_importance = pd.DataFrame(
                    {'Feature': feature_names, 'Value': df.values[0], 'Impact': shap_values[0].values})
                feature_importance['AbsImpact'] = feature_importance['Impact'].abs()
                top_features = feature_importance.sort_values(by='AbsImpact', ascending=False).head(4)

                for _, row in top_features.iterrows():
                    msg = interpret_feature(row['Feature'], row['Value'], row['Impact'])
                    icon = "🔴" if row['Impact'] > 0 else "🔵"
                    st.markdown(f"{icon} **{row['Feature']}**: {msg}")

            with tab2:
                col_img, col_desc = st.columns([1, 2])
                with col_img:
                    st.markdown("**Entropy Bitmap**")
                    fig_bm = plot_entropy_bitmap(temp_filename)
                    st.pyplot(fig_bm)
                with col_desc:
                    st.info(
                        "Uniform/Dark Noise = Packed/Encrypted (Potential Malware)\nStructured Patterns = Normal Code")

            with tab3:
                st.subheader("Indicators of Compromise (IOCs)")
                st.caption("Auto-extracted suspicious artifacts from the binary.")

                # Dynamic Warning display for IOCs
                ioc_found = False
                for category, items in flagged_artifacts.items():
                    if items:
                        ioc_found = True
                        with st.expander(f"🚩 Found {len(items)} {category}", expanded=True):
                            for item in items[:10]:  # Limit to top 10 per category
                                st.code(item)

                if not ioc_found:
                    st.success("✅ No obvious IOCs (IPs, URLs, Scripts) found in string analysis.")

                with st.expander("View All Raw Strings"):
                    st.text_area("Full Dump", "\n".join(all_strings[:500]), height=200)

            os.remove(temp_filename)
        else:
            st.error("Failed to parse file.")