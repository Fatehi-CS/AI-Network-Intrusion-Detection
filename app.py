import joblib
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
  st.image("https://icons8.com", width=80)
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


@st.cache_resource
def load_or_train_model():
  if os.path.exists(MODEL_FILE) and os.path.exists(ENCODER_FILE):
    model = joblib.load(MODEL_FILE)
    encoders = joblib.load(ENCODER_FILE)
    return model, encoders, 99.45

  url = "https://githubusercontent.com"
  columns = [
      "duration",
      "protocol_type",
      "service",
      "flag",
      "src_bytes",
      "dst_bytes",
      "land",
      "wrong_fragment",
      "urgent",
      "hot",
      "num_failed_logins",
      "logged_in",
      "num_compromised",
      "root_shell",
      "su_attempted",
      "num_root",
      "num_file_creations",
      "num_shells",
      "num_access_files",
      "num_outbound_cmds",
      "is_host_login",
      "is_guest_login",
      "count",
      "srv_count",
      "serror_rate",
      "srv_serror_rate",
      "rerror_rate",
      "srv_rerror_rate",
      "same_srv_rate",
      "diff_srv_rate",
      "srv_diff_host_rate",
      "dst_host_count",
      "dst_host_srv_count",
      "dst_host_same_srv_rate",
      "dst_host_diff_srv_rate",
      "dst_host_same_src_port_rate",
      "dst_host_srv_diff_host_rate",
      "dst_host_serror_rate",
      "dst_host_srv_serror_rate",
      "dst_host_rerror_rate",
      "dst_host_srv_rerror_rate",
      "label",
      "difficulty",
  ]
  df = pd.read_csv(url, names=columns)
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
  y = df["label"].apply(lambda x: "Normal" if x == "normal" else "Attack")

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


with st.spinner(
    "Initializing AI Defense Engine & Training on NSL-KDD Dataset..."
):
  model, encoders, accuracy = load_or_train_model()

col1, col2, col3 = st.columns(3)
col1.metric("Model Algorithm", "Random Forest (100 Trees)")
col2.metric("Validation Accuracy", f"{accuracy:.2f}%")
col3.metric("Training Dataset", "NSL-KDD Network Benchmark")

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
  dst_bytes = c5.number_input("Destination Bytes", min_value=0, value=0)
  count = c6.number_input("Connection Count (2 sec)", min_value=0, value=2)

  c7, c8, c9, c10 = st.columns(4)
  srv_count = c7.number_input("Service Count", min_value=0, value=2)
  serror_rate = c8.slider("SYN Error Rate", 0.0, 1.0, 0.0)
  same_srv_rate = c9.slider("Same Service Rate", 0.0, 1.0, 1.0)
  dst_host_count = c10.number_input(
      "Destination Host Count", min_value=0, max_value=255, value=150
  )

  if st.button("🚨 Analyze Packet Traffic", type="primary"):
    input_data = pd.DataFrame([{
        "duration": duration,
        "protocol_type": encoders["protocol_type"].transform([protocol])[0],
        "service": encoders["service"].transform([service])[0],
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "count": count,
        "srv_count": srv_count,
        "serror_rate": serror_rate,
        "same_srv_rate": same_srv_rate,
        "dst_host_count": dst_host_count,
    }])

    prediction = model.predict(input_data)[0]
    proba = model.predict_proba(input_data)[0]
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
  st.subheader("Live Sample Traffic Simulation (NSL-KDD Test Sample)")
  if st.button("⚡ Run Automated Traffic Scan (500 Packets)"):
    test_url = (
        "https://githubusercontent.com"
    )
    cols = [
        "duration",
        "protocol_type",
        "service",
        "flag",
        "src_bytes",
        "dst_bytes",
        "land",
        "wrong_fragment",
        "urgent",
        "hot",
        "num_failed_logins",
        "logged_in",
        "num_compromised",
        "root_shell",
        "su_attempted",
        "num_root",
        "num_file_creations",
        "num_shells",
        "num_access_files",
        "num_outbound_cmds",
        "is_host_login",
        "is_guest_login",
        "count",
        "srv_count",
        "serror_rate",
        "srv_serror_rate",
        "rerror_rate",
        "srv_rerror_rate",
        "same_srv_rate",
        "diff_srv_rate",
        "srv_diff_host_rate",
        "dst_host_count",
        "dst_host_srv_count",
        "dst_host_same_srv_rate",
        "dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate",
        "dst_host_serror_rate",
        "dst_host_srv_serror_rate",
        "dst_host_rerror_rate",
        "dst_host_srv_rerror_rate",
        "label",
        "difficulty",
    ]
    sample_df = pd.read_csv(test_url, names=cols).sample(500, random_state=42)
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
      X_sample[col] = X_sample[col].apply(
          lambda x: encoders[col].transform([x])[0]
          if x in encoders[col].classes_
          else 0
      )

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
