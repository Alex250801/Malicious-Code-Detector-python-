import streamlit as st
import pandas as pd
import re
import math
from datetime import datetime

# "Fingerprinting" 
dev_fingerprints = {
    "marian_popescu": {
        "role": "Senior Dev",
        "trusted": True,
        "typical_hours": range(9, 18), 
        "avg_changes": 150
    },
    "ion_popescu": {
        "role": "Junior Dev",
        "trusted": True,
        "typical_hours": range(10, 19),
        "avg_changes": 50
    }
}
# calculul entropiei Shannon textului
def calculate_entropy(text):
    if not text: return 0
    probs = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log(p, 2) for p in probs)

def calculate_risk(author, diff, commit_msg):
    alerts = []
    
    # 1. Analiza Fingerprint (Comportament)
    hour_now = datetime.now().hour

    if author not in dev_fingerprints:
        return 100, ["🚨 [CRITICAL] Autor Necunoscut: Acest utilizator nu există în baza de date. Acces refuzat conform politicii Zero Trust."]
    
    score = 0
    
    if author in dev_fingerprints:
        fp = dev_fingerprints[author]
        if hour_now not in fp["typical_hours"]:
            score += 30
            alerts.append(f"⚠️ Anomalie Orare: {author} lucrează în afara orelor obișnuite.")
        if len(diff) > fp["avg_changes"] * 5:
            score += 25
            alerts.append(f"⚠️ Anomalie Volum: Modificare masivă de cod față de media autorului.")
    else:
        score += 20
        alerts.append("ℹ️ Autor Nou: Nu există fingerprint pentru acest developer.")

    # Detectie Criptare / Verificare Entropie
    entropy_val = calculate_entropy(diff)
    if entropy_val > 4.8: # Prag statistic pentru cod care "arată" suspect/criptat
        score += 40
        alerts.append(f"🧬 Anomalie Entropie ({entropy_val:.2f}): Codul pare obfuscat sau conține date criptate.")

    # Protectia fisierelor si Activelor Critice 
    critical_assets = ["config", ".env", "password", "secret", "token", "database"]
    if any(asset in diff.lower() or asset in commit_msg.lower() for asset in critical_assets):
        score += 35
        alerts.append("🔑 Risc Ridicat: Modificare detectată în active critice sau fișiere de configurare.")
        
    # 2. Analiza de Cod (Pattern-uri Suspecte)
    suspicious = {"eval(": 40, "base64.b64decode": 35, "socket.connect": 30, "chmod +x": 45,"os.system(": 40, "subprocess.Popen": 40, "import ctypes": 30,
                   "os.spawnv(":35, "marshal.loads(":40,"zlib.decompress(data).decode()":40, "exec(": 45}
    for pattern, weight in suspicious.items():
        if pattern in diff:
            score += weight
            alerts.append(f"🚨 Tipar Malițios: Detectat '{pattern}' în cod.")

    return min(score, 100), alerts

# Interfața Streamlit
st.set_page_config(page_title="Malicious Code Detector", layout="wide")
st.title("🛡️ Sentinel Code: Pre-Release Detection")

col1, col2 = st.columns([1, 2])

with col1:
    st.header("Input Commit")
    author = st.text_input("Author Name", "ion_popescu")
    commit_msg = st.text_input("Commit Message", "Quick fix in core")
    diff_content = st.text_area("Code Diff (Changes)", "print('Hello World')\neval(input())", height=200)
    
    analyze_btn = st.button("Analyze Commit")

if analyze_btn:
    with col2:
        risk_score, alerts = calculate_risk(author, diff_content, commit_msg)
        
        st.header("Risk Analysis Report")
        
        # Indicator Vizual
        color = "green" if risk_score < 30 else "orange" if risk_score < 60 else "red"
        st.markdown(f"<h1 style='color: {color};'>Risk Score: {risk_score}/100</h1>", unsafe_allow_html=True)
        
        if alerts:
            for alert in alerts:
                st.write(alert)
        else:
            st.success("Nu au fost detectate anomalii majore.")
            
        st.info("Rezultatul a fost trimis către pipeline-ul CI/CD.")