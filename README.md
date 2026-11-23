# 🛡️ AI-Powered Network Intrusion Detection System (AI-NIDS)

**Engineered & Developed by:** Fatehi Abdulfattah Mohammed Ali Alshami (`@Fatehi-CS`)  
**Part of:** *The Digital Shield* Cybersecurity Initiative  

🔗 **Live Interactive Web Application:** https://fatehi-ai-nids.streamlit.app



---

## 📌 Project Overview
**AI-NIDS** is a machine learning-based cybersecurity defense system designed to detect and classify network intrusions in real time. Built as a practical application of concepts from the **Cisco Junior Cybersecurity Analyst** and **Cisco Modern AI Principles** pathways, this system analyzes key network packet metrics to distinguish between legitimate (`Normal`) traffic and malicious cyberattacks (`Attack`) such as SYN floods, DoS, and network probing.

---

## ⚙️ System Architecture & Methodology
1. **Feature Engineering (10 Core Network Metrics):**  
   Extracts and processes critical traffic attributes inspired by the **NSL-KDD** benchmark dataset: `duration`, `protocol_type`, `service`, `src_bytes`, `dst_bytes`, `count`, `srv_count`, `serror_rate`, `same_srv_rate`, and `dst_host_count`.
2. **Data Preprocessing:**  
   Encodes categorical network protocols (`TCP`, `UDP`, `ICMP`) and services into numerical representations using `LabelEncoder`.
3. **Machine Learning Engine:**  
   Trains a **Random Forest Classifier** (100 decision trees) using `scikit-learn` to achieve high-accuracy binary classification with probability confidence scores.
4. **Interactive Defense Dashboard:**  
   Built with **Streamlit** and **Plotly** to provide:
   - **Single Packet Inspector:** Real-time simulation and threat classification of individual network packets with actionable mitigation recommendations.
   - **Batch Network Traffic Analyzer:** Automated scanning of 500-packet traffic streams with visual threat distribution analytics.

---

## 🛠️ Tech Stack
- **Language:** Python
- **Machine Learning:** Scikit-Learn (`RandomForestClassifier`), Pandas, NumPy
- **Visualization & UI:** Streamlit, Plotly
- **Deployment:** Streamlit Community Cloud

---

## 🎓 About the Developer
Developed independently via mobile workstation by **Fatehi Abdulfattah Mohammed Ali Alshami** to advance cybersecurity awareness and infrastructure protection.
