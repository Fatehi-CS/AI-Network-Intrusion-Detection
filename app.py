import joblib
import numpy as np
import os
import pandas as pd
import plotly.express as px
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import streamlit as st

st.set_page_config(
    page_title="AI-NIDS | Fatehi Alshami", page_icon="🛡️", layout="wide"
)

# الشريط الجانبي للتعريف بالمطور
with st.sidebar:
  st.markdown("## 🛡️ AI-NIDS Defense")
  st.title("Developer Profile")
  st.markdown("**Engineered by:**\nFatehi Abdulfattah Mohammed Ali Alshami")
  st.markdown("**GitHub:** `@Fatehi-CS`")
  st.markdown("**Initiative:** The Digital Shield")
  st.divider()
  st.markdown("**Certifications:**")
  st.markdown("- Cisco Junior Cybersecurity Analyst")
  st.markdown("- Cisco Modern AI Principles")
  st.divider()
  st.caption("© 2026 Fatehi Alshami | AI & Cybersecurity Research")

st.title("🛡️ AI-Powered Network Intrusion Detection System (AI-NIDS)")
st.markdown(
    "### Intelligent Cyber Threat Analysis & Real-Time Traffic Classification"
)
st.caption(
    "🚀 **Engineered & Developed by Fatehi Abdulfattah Mohammed Ali Alshami"
    " (@Fatehi-CS)** | Part of The Digital Shield Ecosystem"
)

MODEL_FILE = "nids_model.joblib"
ENCODER_FILE = "encoders.joblib"


def generate_nslkdd_benchmark_data(n_samples=6000):
  np.random.seed(42)
  n_normal = int(n_samples * 0.55)
  n_attack = n_samples - n_normal

  normal_df = pd.DataFrame({
      "duration": np.random.exponential(scale=12, size=n_normal).astype(int),
      "protocol_type": np.random.choice(
          ["tcp", "udp", "icmp"], size=n_normal, p=[0.82, 0.15, 0.03]
      ),
      "service": np.random.choice(
          ["http", "domain_u", "smtp", "ftp_data", "ssh"],
          size=n_normal,
          p=[0.6, 0.2, 0.1, 0.05, 0.05],
      ),
      "src_bytes": np.random.lognormal(mean=6.2, sigma=1.1, size=n_normal).astype(
          int
      ),
      "dst_bytes": np.random.lognormal(mean=7.5, sigma=1.3, size=n_normal).astype(
          int
      ),
      "count": np.random.randint(1, 25, size=n_normal),
      "srv_count": np.random.randint(1, 25, size=n_normal),
      "serror_rate": np.random.uniform(0.0, 0.08, size=n_normal).round(2),
      "same_srv_rate": np.random.uniform(0.85, 1.0, size=n_normal).round(2),
      "dst_host_count": np.random.randint(10, 180, size=n_normal),
      "label": ["Normal"] * n_normal,
  })

  attack_df = pd.DataFrame({
      "duration": np.random.randint(0, 5, size=n_attack),
      "protocol_type": np.random.choice(
          ["tcp", "udp", "icmp"], size=n_attack, p=[0.70, 0.10, 0.20]
      ),
      "service": np.random.choice(
          ["private", "ecr_i", "http", "ftp", "telnet", "finger"], size=n_attack
      ),
      "src_bytes": np.random.randint(0, 1200, size=n_attack),
      "dst_bytes": np.random.randint(0, 100, size=n_attack),
      "count": np.random.randint(80, 511, size=n_attack),
      "srv_count": np.random.randint(1, 40, size=n_attack),
      "serror_rate": np.random.uniform(0.65, 1.0, size=n_attack).round(2),
      "same_srv_rate": np.random.uniform(0.0, 0.35, size=n_attack).round(2),
      "dst_host_count": np.random.randint(180, 256, size=n_attack),
      "label": ["Attack"] * n_attack,
  })

  df = (
      pd.concat([normal_df, attack_df], ignore_index=True)
      .sample(frac=1, random_state=42)
      .reset_index(drop=True)
  )
  return df


@st.cache_resource
def load_or_train_model():
  df = generate_nslkdd_benchmark_data(8000)
  features = [
      "duration",
      "protocol_type",
      "service",
      "src_bytes",
      "dst_bytes",
      "count",
      "srv_count",
      "serror_rate",
      "same_srv_rate",
      "dst_host_count",
  ]
  X = df[features].copy()
  y = df["label"]

  encoders = {}
  for col in ["protocol_type", "service"]:
    le = LabelEncoder()
    X[col] = le.fit_transform(X[col])
    encoders[col] = le

  X_train, X_test, y_train, y_test = train_test_split(
      X, y, test_size=0.2, random_state=42
  )
  model = RandomForestClassifier(n_estimators=100, random_state=42)
  model.fit(X_train, y_train)
  acc = accuracy_score(y_test, model.predict(X_test)) * 100

  joblib.dump(model, MODEL_FILE)
  joblib.dump(encoders, ENCODER_FILE)
  return model, encoders, acc


with st.spinner("Initializing AI Defense Engine & Training Random Forest..."):
  model, encoders, accuracy = load_or_train_model()

col1, col2, col3 = st.columns(3)
col1.metric("Model Algorithm", "Random Forest (100 Trees)")
col2.metric("Validation Accuracy", f"{accuracy:.2f}%")
col3.metric("Features Analyzed", "10 Core Network Metrics")

st.divider()

tab1, tab2 = st.tabs(
    ["🔍 Single Packet Inspector", "📊 Batch Network Traffic Analyzer"]
)

with tab1:
  st.subheader("Simulate & Analyze Network Packet Parameters")
  c1, c2, c3 = st.columns(3)
  duration = c1.number_input("Connection Duration (sec)", min_value=0, value=0)
  protocol = c2.selectbox(
      "Protocol Type", list(encoders["protocol_type"].classes_)
  )
  service = c3.selectbox("Network Service", list(encoders["service"].classes_))

  c4, c5, c6 = st.columns(3)
  src_bytes = c4.number_input("Source Bytes", min_value=0, value=491)
  dst_bytes = c5.number_input("Destination Bytes", min_value=0, value=1200)
  count = c6.number_input("Connection Count (2 sec)", min_value=0, value=4)

  c7, c8, c9, c10 = st.columns(4)
  srv_count = c7.number_input("Service Count", min_value=0, value=4)
  serror_rate = c8.slider("SYN Error Rate", 0.0, 1.0, 0.0)
  same_srv_rate = c9.slider("Same Service Rate", 0.0, 1.0, 1.0)
  dst_host_count = c10.number_input(
      "Destination Host Count", min_value=0, max_value=255, value=80
  )

  if st.button("🚨 Analyze Packet Traffic", type="primary"):
    input_data = pd.DataFrame([{
        "duration": duration,
        "protocol_type": encoders["protocol_type"].transform([protocol]),
        "service": encoders["service"].transform([service]),
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "count": count,
        "srv_count": srv_count,
        "serror_rate": serror_rate,
        "same_srv_rate": same_srv_rate,
        "dst_host_count": dst_host_count,
    }])

    prediction = model.predict(input_data)
    proba = model.predict_proba(input_data)
    confidence = max(proba) * 100

    if prediction == "Normal":
      st.success(
          f"✅ **SAFE TRAFFIC (Normal)** — Confidence: **{confidence:.2f}%**"
      )
      st.info("No anomalous patterns or intrusion signatures detected.")
    else:
      st.error(
          f"⚠️ **CYBER ATTACK DETECTED (Intrusion)** — Confidence:"
          f" **{confidence:.2f}%**"
      )
      st.warning(
          "**Recommended Defense Action:** Isolate source IP, inspect firewall"
          " logs for SYN flood / probing anomalies, and apply rate-limiting."
      )

with tab2:
  st.subheader("Live Simulated Network Traffic Stream (500 Packets)")
  if st.button("⚡ Run Automated Traffic Scan (500 Packets)"):
    sample_df = generate_nslkdd_benchmark_data(500)
    features = [
        "duration",
        "protocol_type",
        "service",
        "src_bytes",
        "dst_bytes",
        "count",
        "srv_count",
        "serror_rate",
        "same_srv_rate",
        "dst_host_count",
    ]
    X_sample = sample_df[features].copy()

    for col in ["protocol_type", "service"]:
      X_sample[col] = encoders[col].transform(X_sample[col])

    preds = model.predict(X_sample)
    sample_df["AI_Prediction"] = preds

    summary = sample_df["AI_Prediction"].value_counts().reset_index()
    summary.columns = ["Traffic Type", "Packet Count"]

    c_left, c_right = st.columns(2)
    with c_left:
      fig = px.pie(
          summary,
          values="Packet Count",
          names="Traffic Type",
          color="Traffic Type",
          color_discrete_map={"Normal": "#2ecc71", "Attack": "#e74c3c"},
          title="Detected Traffic Distribution",
      )
      st.plotly_chart(fig, use_container_width=True)
    with c_right:
      st.dataframe(
          sample_df[
              ["protocol_type", "service", "src_bytes", "count", "AI_Prediction"]
          ].head(15),
          use_container_width=True,
      )

st.divider()
st.markdown(
    "<center>Developed with ❤️ by <b>Fatehi Abdulfattah Mohammed Ali"
    " Alshami</b> | Powered by Machine Learning & Streamlit</center>",
    unsafe_allow_html=True,
)
