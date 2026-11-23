import streamlit as st
import socket
import urllib.request
import json
import re

st.set_page_config(
    page_title="AI-NIDS | Wi-Fi & IP Safety Checker",
    page_icon="🛡️",
    layout="centered"
)

st.markdown("""
<style>
    .main-title { text-align: center; font-size: 2.1rem; font-weight: 800; color: #1E88E5; margin-bottom: 0.2rem; }
    .sub-title { text-align: center; font-size: 1.05rem; color: #90A4AE; margin-bottom: 1.5rem; }
    .safe-card { padding: 1.4rem; border-radius: 12px; background-color: rgba(46, 125, 50, 0.15); border: 2px solid #2E7D32; margin-top: 1.2rem; }
    .danger-card { padding: 1.4rem; border-radius: 12px; background-color: rgba(198, 40, 40, 0.15); border: 2px solid #C62828; margin-top: 1.2rem; }
    .warn-card { padding: 1.4rem; border-radius: 12px; background-color: rgba(245, 124, 0, 0.15); border: 2px solid #F57C00; margin-top: 1.2rem; }
</style>
""", unsafe_allow_html=True)

col_spacer, col_lang = st.columns([3, 1.3])
with col_lang:
    lang = st.radio("Language", ["English", "العربية"], horizontal=True, label_visibility="collapsed")

is_ar = (lang == "العربية")

with st.sidebar:
    st.markdown("# 🛡️")
    st.title("The Digital Shield")
    if is_ar:
        st.markdown("**نظام فحص أمان الشبكات وعناوين الـ IP (AI-NIDS)**")
        st.divider()
        st.markdown("### 👨‍💻 المطور")
        st.write("**Fatehi Abdulfattah Mohammed Ali Alshami**")
        st.markdown("🔗 [مستودع الكود على GitHub](https://github.com)")
        st.divider()
        st.markdown("### 🎓 الشهادات")
        st.info("• محلل أمن سيبراني معتمد من سيسكو\n• مبادئ الذكاء الاصطناعي الحديثة من سيسكو")
    else:
        st.markdown("**Pre-Connection Wi-Fi & IP Security Scanner (AI-NIDS)**")
        st.divider()
        st.markdown("### 👨‍💻 Developer")
        st.write("**Fatehi Abdulfattah Mohammed Ali Alshami**")
        st.markdown("🔗 [GitHub Repository](https://github.com)")
        st.divider()
        st.markdown("### 🎓 Certifications")
        st.info("• Cisco Junior Cybersecurity Analyst\n• Cisco Modern AI Principles")

if is_ar:
    st.markdown('<div class="main-title">🛡️ فاحص أمان الشبكة والـ IP</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">تأكد من أمان أي شبكة Wi-Fi في كافيه أو مكان عام عبر فحص عنوان الـ IP الخاص بها</div>', unsafe_allow_html=True)
    input_label = "أدخل أو الصق عنوان الـ IP الخاص بالشبكة هنا:"
    input_placeholder = "مثال: 8.8.8.8  أو  185.240.64.12"
    btn_text = "🔍 افحص أمان الشبكة الآن"
else:
    st.markdown('<div class="main-title">🛡️ Wi-Fi & Network IP Safety Scanner</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">Verify the security of any public or café Wi-Fi network by inspecting its IP address before trusting it</div>', unsafe_allow_html=True)
    input_label = "Enter or Paste Network IP Address:"
    input_placeholder = "Example: 8.8.8.8 or 185.240.64.12"
    btn_text = "🔍 Scan Network IP Now"

ip_input = st.text_input(input_label, placeholder=input_placeholder).strip()

def is_valid_ip(ip):
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(part) <= 255 for part in parts)

def is_private_ip(ip):
    parts = [int(x) for x in ip.split(".")]
    if parts[0] == 10:
        return True
    if parts[0] == 172 and (16 <= parts[1] <= 31):
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 127:
        return True
    return False

if st.button(btn_text, type="primary", use_container_width=True):
    if not ip_input:
        st.warning("⚠️ يرجى إدخال عنوان IP أولاً لبدء الفحص." if is_ar else "⚠️ Please enter an IP address first to start scanning.")
    elif not is_valid_ip(ip_input):
        st.error("❌ صيغة عنوان الـ IP غير صحيحة!" if is_ar else "❌ Invalid IPv4 address format!")
    elif is_private_ip(ip_input):
        if is_ar:
            st.markdown(f'<div class="warn-card" dir="rtl"><h3>⚠️ تنبيه: عنوان IP محلي داخلي ({ip_input})</h3><p>هذا عنوان الراوتر الداخلي (Local Gateway). للحصول على الـ IP العام وفحصه، ابحث في المتصفح عن <b>What is my IP</b> وانسخه هنا.</p></div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="warn-card"><h3>⚠️ Notice: Private Local IP ({ip_input})</h3><p>This is an internal router gateway address. To scan the network Public IP, search <b>What is my IP</b> in your browser and paste it here.</p></div>', unsafe_allow_html=True)
    else:
        spinner_msg = "جاري فحص الشبكة والمنافذ..." if is_ar else "Scanning network IP and ports..."
        with st.spinner(spinner_msg):
            risk_score = 0
            findings = []
            isp_name = "غير معروف" if is_ar else "Unknown"
            country_name = "غير معروف" if is_ar else "Unknown"

            try:
                url = f"https://ipwho.is{ip_input}"
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=5) as response:
                    geo_data = json.loads(response.read().decode("utf-8"))
                    if geo_data.get("success"):
                        conn = geo_data.get("connection", {})
                        isp_name = conn.get("isp") or conn.get("org") or isp_name
                        country_name = geo_data.get("country") or country_name
                        sec = geo_data.get("security", {})
                        if sec.get("proxy") or sec.get("vpn") or sec.get("tor"):
                            risk_score += 40
                            findings.append("🚨 **تم رصد بروكسي/VPN مشبوه**" if is_ar else "🚨 **Proxy/VPN Detected**")
                        if sec.get("hosting"):
                            risk_score += 20
                            findings.append("⚠️ **خادم استضافة سحابي (Hosting IP)**" if is_ar else "⚠️ **Cloud Hosting IP Detected**")
            except Exception:
                findings.append("ℹ️ تعذر جلب بيانات المزود الخارجي." if is_ar else "ℹ️ External ISP lookup unavailable.")

            critical_ports = {
                21: ("FTP (نقل ملفات غير مشفر)", "FTP (Unencrypted)"),
                22: ("SSH (تحكم عن بُعد)", "SSH (Remote Access)"),
                23: ("Telnet (خطير جداً)", "Telnet (Critical)"),
                80: ("HTTP (غير مشفر)", "HTTP (Unencrypted)"),
                445: ("SMB (مشاركة ملفات)", "SMB (File Sharing)"),
                3389: ("RDP (سطح مكتب بعيد)", "RDP (Remote Desktop)"),
                8080: ("HTTP-Proxy (بروكسي مفتوح)", "HTTP-Proxy (Open Proxy)")
            }

            high_risk_list = (21, 23, 445, 3389)
            open_ports = []

            for port, (desc_ar, desc_en) in critical_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    if sock.connect_ex((ip_input, port)) == 0:
                        desc = desc_ar if is_ar else desc_en
                        open_ports.append(f"Port {port}: {desc}")
                        risk_score += 30 if port in high_risk_list else 15
                    sock.close()
                except Exception:
                    pass

            if open_ports:
                ports_str = ", ".join(open_ports)
                findings.append(f"🔌 **منافذ مفتوحة ({len(open_ports)}):** {ports_str}" if is_ar else f"🔌 **Open Ports ({len(open_ports)}):** {ports_str}")
            else:
                findings.append("🔒 **جميع المنافذ الحساسة مغلقة ومحمية.**" if is_ar else "🔒 **All critical ports are closed and protected.**")

            risk_score = min(risk_score, 100)

            st.divider()
            col1, col2, col3 = st.columns(3)
            col1.metric("مزود الخدمة (ISP)" if is_ar else "ISP Provider", isp_name[:22])
            col2.metric("الدولة (Country)" if is_ar else "Country", country_name)
            col3.metric("مؤشر الخطورة" if is_ar else "Risk Score", f"{risk_score}%")

            if risk_score >= 50:
                if is_ar:
                    st.markdown(f'<div class="danger-card" dir="rtl"><h3>🚨 تحذير خطير: شبكة غير آمنة! ({risk_score}%)</h3><p>لا تعتمد على هذه الشبكة ولا تُدخل فيها بياناتك الشخصية.</p></div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="danger-card"><h3>🚨 High Risk Warning: Unsafe Network! ({risk_score}%)</h3><p>Do not trust this network with personal or banking data.</p></div>', unsafe_allow_html=True)
            elif risk_score >= 20:
                if is_ar:
                    st.markdown(f'<div class="warn-card" dir="rtl"><h3>⚠️ شبكة متوسطة الأمان ({risk_score}%)</h3><p>استخدمها بحذر ويُنصح بتشغيل <b>VPN</b> أثناء التصفح.</p></div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="warn-card"><h3>⚠️ Moderate Risk ({risk_score}%)</h3><p>Proceed with caution and use a trusted <b>VPN</b>.</p></div>', unsafe_allow_html=True)
            else:
                if is_ar:
                    st.markdown(f'<div class="safe-card" dir="rtl"><h3>✅ الشبكة آمنة ومحمية ({risk_score}%)</h3><p>مزود الخدمة موثوق والمنافذ الخطيرة مغلقة.</p></div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="safe-card"><h3>✅ Network Appears Safe ({risk_score}%)</h3><p>Legitimate provider and critical ports are closed.</p></div>', unsafe_allow_html=True)

            st.markdown("#### 📋 تفاصيل تقرير الفحص:" if is_ar else "#### 📋 Detailed Security Report:")
            for item in findings:
                st.markdown(item)
# END OF CODE
