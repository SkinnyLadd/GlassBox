import streamlit as st
import pandas as pd
import joblib
import json
import os
import shap
import matplotlib.pyplot as plt

from extractor import extract_features

# --- PAGE CONFIG ---
st.set_page_config(page_title="GlassBox AI Antivirus", page_icon="🛡️", layout="wide")


# --- 1. THE LOGIC BRAIN (Contextual Interpretations) ---
def interpret_feature(feature_name, value, impact_score):
    """
    Returns a human-readable string explaining WHY the value is Good or Bad.
    """
    # Is this feature pushing towards Malware (Risk) or Safe (Blue)?
    is_risk = impact_score > 0

    # --- LOGIC FOR ENTROPY (E_file, E_text, E_data) ---
    if "E_" in feature_name or "Entropy" in feature_name:
        if value > 7.0 and is_risk:
            return "This section is extremely random (Entropy > 7.0). This usually means the code is 'Packed' (encrypted) to hide a virus."
        elif value < 6.0 and not is_risk:
            return "The entropy is low/normal, which looks like standard, unhidden computer code."

    # --- LOGIC FOR FILE SIZE ---
    if feature_name == "filesize":
        if value < 20000 and is_risk:  # Less than 20KB
            return "The file is suspiciously small. Many malware 'stagers' are tiny scripts."
        elif value > 1000000 and not is_risk:  # Greater than 1MB
            return "The file is large. Most malware tries to be small. Large installers are often legitimate."

    # --- LOGIC FOR CHECKSUM ---
    if feature_name == "CheckSum":
        if value == 0 and is_risk:
            return "The Checksum is 0. Professional software usually fills this field; 0 implies a lazy/malicious compilation."
        elif value > 0 and not is_risk:
            return "A valid, non-zero checksum is present, suggesting the file header was generated correctly."

    # --- LOGIC FOR DLL CHARACTERISTICS (OH_DLLchar) ---
    if "OH_DLLchar" in feature_name:
        if value == 1 and not is_risk:
            return "This security flag (e.g., ASLR/DEP) is ON, which is standard for modern safe software."
        elif value == 0 and is_risk:
            return "This modern security flag is MISSING, which makes the file look old or suspicious."

    # --- LOGIC FOR SECTIONS ---
    if feature_name == "sus_sections":
        if value > 0 and is_risk:
            return f"Found {int(value)} non-standard section(s). Malware often creates weirdly named sections (e.g., '.upx') to hide."

    # --- GENERIC FALLBACK ---
    if is_risk:
        return f"The value '{value:.4f}' is common in Malware, but rare in Safe files."
    else:
        return f"The value '{value:.4f}' is typical for benign, safe software."


# --- 2. LOAD RESOURCES ---
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

# --- 3. UI HEADER ---
st.title("🛡️ GlassBox Malware Detector")
st.markdown("### Explainable AI (XAI) Security Engine")

# --- 4. MAIN APP ---
uploaded_file = st.file_uploader("Upload a PE file (.exe, .dll)", type=["exe", "dll"])

if uploaded_file is not None:
    temp_filename = "temp_scan_file.exe"
    with open(temp_filename, "wb") as f:
        f.write(uploaded_file.getbuffer())

    with st.spinner("Analyzing Headers..."):
        # A. EXTRACT
        feature_vector = extract_features(temp_filename)

        # B. PREDICT
        if feature_vector:
            df = pd.DataFrame([feature_vector], columns=feature_names)
            prediction = model.predict(df)[0]
            probability = model.predict_proba(df)[0][1]  # Risk Score

            os.remove(temp_filename)

            # --- C. DASHBOARD ---
            st.divider()

            # 1. VERDICT
            col1, col2 = st.columns([1, 2])

            with col1:
                st.subheader("Verdict")
                if prediction == 1:
                    st.error("🚨 MALICIOUS")
                    st.metric("Confidence", f"{probability * 100:.2f}%")
                else:
                    st.success("✅ BENIGN")
                    st.metric("Safety Score", f"{(1 - probability) * 100:.2f}%")

            with col2:
                # 2. WATERFALL PLOT
                st.subheader("Decision Path")
                explainer = shap.TreeExplainer(model)
                shap_values = explainer(df)

                fig, ax = plt.subplots(figsize=(8, 3))
                shap.plots.waterfall(shap_values[0], max_display=7, show=False)
                st.pyplot(fig, clear_figure=True)

            # 3. INTERPRETATION TABLE (THE NEW LOGIC)
            st.divider()
            st.subheader("🔍 Deep Dive Analysis")
            st.caption("Contextual reasoning behind the top factors.")

            # Get data
            feature_importance = pd.DataFrame({
                'Feature': feature_names,
                'Value': df.values[0],
                'Impact': shap_values[0].values
            })
            feature_importance['AbsImpact'] = feature_importance['Impact'].abs()
            top_features = feature_importance.sort_values(by='AbsImpact', ascending=False).head(5)

            for index, row in top_features.iterrows():
                fname = row['Feature']
                val = row['Value']
                impact = row['Impact']

                # Get the Dynamic Interpretation
                context_msg = interpret_feature(fname, val, impact)

                # Visuals
                color = "🔴" if impact > 0 else "🔵"
                status = "Risk Factor" if impact > 0 else "Safety Factor"

                with st.expander(f"{color} {fname} ({status})"):
                    col_a, col_b = st.columns([1, 3])
                    with col_a:
                        st.metric("Value", f"{val:.4f}")
                    with col_b:
                        st.markdown(f"**Reasoning:** {context_msg}")

        else:
            st.error("❌ Failed to parse file.")