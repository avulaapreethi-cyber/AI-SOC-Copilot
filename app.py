import streamlit as st
import requests
import re

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3"

st.set_page_config(
    page_title="AI SOC Copilot",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
.stApp {
    background-color: #0b0f17;
    color: white;
}
textarea {
    background-color: #1f2430 !important;
    color: white !important;
}
.stButton button {
    background-color: #111827;
    color: white;
    border: 1px solid #4b5563;
    border-radius: 8px;
    padding: 10px 18px;
}
.result-box {
    background-color: #111827;
    padding: 25px;
    border-radius: 12px;
    border: 1px solid #374151;
    color: #e5e7eb;
    line-height: 1.7;
}
.footer {
    color: #9ca3af;
    margin-top: 40px;
}
</style>
""", unsafe_allow_html=True)


def extract_iocs(text):
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    urls = re.findall(r"https?://[^\s]+", text)
    hashes = re.findall(r"\b[a-fA-F0-9]{32,64}\b", text)

    return {
        "ips": list(set(ips)),
        "urls": list(set(urls)),
        "hashes": list(set(hashes))
    }


def show_severity_badge(result):
    text = result.lower()

    if "critical" in text:
        st.error("🔴 Severity: Critical")
    elif "high" in text:
        st.warning("🟠 Severity: High")
    elif "medium" in text:
        st.info("🟡 Severity: Medium")
    elif "low" in text:
        st.success("🟢 Severity: Low")
    else:
        st.info("⚪ Severity: Unknown")


def analyze_with_ollama(alert_text):
    prompt = f"""
You are an expert SOC Analyst.

Analyze the following security alert/log:

{alert_text}

Give the output in this exact format:

1. Threat Summary
2. Severity Level: Critical / High / Medium / Low
3. MITRE ATT&CK Mapping
4. Indicators of Compromise
5. Why this is suspicious
6. Recommended Investigation Steps
7. Recommended Response Actions
8. Final SOC Analyst Verdict
"""

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL_NAME,
            "prompt": prompt,
            "stream": False
        },
        timeout=120
    )

    if response.status_code != 200:
        return f"Ollama Error: {response.text}"

    return response.json().get("response", "No response received from Ollama.")


st.markdown("# 🛡️ AI SOC Copilot")
st.markdown("## Security Analyst Assistant")
st.divider()

user_input = st.text_area(
    "Enter Security Alert, IOC, Log, or Investigation Question",
    height=220,
    placeholder="Example: PowerShell.exe -EncodedCommand SQBFAFgA executed from WINWORD.EXE and connected to 185.220.101.45"
)

if st.button("Analyze Alert"):
    if not user_input.strip():
        st.warning("Please enter a security alert or log first.")
    else:
        with st.spinner("Analyzing alert using local Llama3 model..."):
            try:
                iocs = extract_iocs(user_input)
                result = analyze_with_ollama(user_input)

                st.success("Analysis completed.")

                show_severity_badge(result)

                col1, col2, col3 = st.columns(3)
                col1.metric("Detected IPs", len(iocs["ips"]))
                col2.metric("Detected URLs", len(iocs["urls"]))
                col3.metric("Detected Hashes", len(iocs["hashes"]))

                if iocs["ips"] or iocs["urls"] or iocs["hashes"]:
                    st.subheader("Extracted IOCs")
                    st.json(iocs)

                st.subheader("AI SOC Analysis")
                st.markdown(
                    f"<div class='result-box'>{result}</div>",
                    unsafe_allow_html=True
                )

            except requests.exceptions.ConnectionError:
                st.error("Ollama is not running. Open another Command Prompt and run: ollama run llama3")
            except Exception as e:
                st.error(f"Error: {e}")

st.divider()
st.markdown(
    "<div class='footer'>AI SOC Copilot | Powered by Ollama + Llama3 + Streamlit</div>",
    unsafe_allow_html=True
)