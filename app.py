import streamlit as st
import socket
import urllib.request
import json
import re

# Page Configuration
st.set_page_config(
    page_title="AI-NIDS | Wi-Fi & IP Safety Checker",
    page_icon="🛡️",
    layout="centered"
)

# Custom CSS
st.markdown("""
<style>
    .main-title {
        text-align: center;
        font-size: 2.1rem;
        font-weight: 800;
        color: #1E88E5;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        text-align: center;
        font-size: 1.05rem;
        color: #90A4AE;
        margin-bottom: 1.5rem;
    }
    .safe-card {
        padding: 1.4rem;
        border-radius: 12px;
        background-color: rgba(46, 125, 50, 0.15);
        border: 2px solid #2E7D32;
        margin-top: 1.2rem;
    }
    .danger-card {
        padding: 1.4rem;
        border-radius: 12px;
        background-color: rgba(198, 40, 40, 0.15);
        border: 2px solid #C62828;
        margin-top: 1.2rem;
    }
    .warn-card {
        padding: 1.4rem;
        border-radius: 12px;
        background-color: rgba(245, 124, 0, 0.15);
        border: 2px solid #F57C00;
        margin-top: 1.2rem;
    }
</style>
""", unsafe_allow_html=True)

# Top Language Switcher (Default: English)
col_spacer, col_lang = st.columns([3, 1.3])
with col_lang:
    lang = st.radio("🌐 Language", ["English", "العربية"], horizontal=True, label_visibility="collapsed")

is_ar = (lang == "العربية")

# Sidebar - Developer Info
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

# Main Header
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

# Helper functions
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

# Scan Action
if st.button(btn_text, type="primary", use_container_width=True):
    if not ip_input:
        st.warning("⚠️ يرجى إدخال عنوان IP أولاً لبدء الفحص." if is_ar else "⚠️ Please enter an IP address first to start scanning.")
    elif not is_valid_ip(ip_input):
        st.error("❌ صيغة عنوان الـ IP غير صحيحة! يرجى التأكد من كتابته بشكل صحيح (مثل: 8.8.8.8)." if is_ar else "❌ Invalid IP address format! Please enter a valid IPv4 address (e.g., 8.8.8.8).")
    elif is_private_ip(ip_input):
        if is_ar:
            st.markdown(f"""
            <div class="warn-card" dir="rtl">
                <h3>⚠️ تنبيه: هذا عنوان IP محلي داخلي ({ip_input})</h3>
                <p><b>ماذا يعني هذا؟</b> هذا عنوان الراوتر الداخلي للشبكة المحلية (Local Gateway) وليس عنوان الإنترنت العام (Public IP).</p>
                <ul>
                    <li>إذا كنت في <b>كافيه أو شبكة عامة</b>: تأكد أن الشبكة محمية بكلمة مرور (WPA2/WPA3) وليست مفتوحة، ولا تدخل بياناتك البنكية عليها.</li>
                    <li>للحصول على <b>الـ IP العام</b> للشبكة وفحصه من الخارج: افتح متصفحك واكتب <i>"What is my IP"</i> ثم انسخ الرقم الظاهر والصقه هنا.</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="warn-card">
                <h3>⚠️ Notice: Private Local IP Address ({ip_input})</h3>
                <p><b>What does this mean?</b> This is an internal local router gateway address, not the network's external Public IP.</p>
                <ul>
                    <li>If you are on a <b>café or public Wi-Fi</b>: Ensure the network uses WPA2/WPA3 encryption and avoid entering sensitive banking credentials.</li>
                    <li>To scan the network's <b>Public IP</b>: Search <i>"What is my IP"</i> in your browser, copy the public address, and paste it here.</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
    else:
        spinner_msg = "جاري فحص الشبكة والمنافذ المفتوحة وهوية المزود..." if is_ar else "Scanning network IP, open ports, and ISP reputation..."
        with st.spinner(spinner_msg):
            risk_score = 0
            findings = []

            isp_name = "غير معروف" if is_ar else "Unknown"
            country_name = "غير معروف" if is_ar else "Unknown"

            # Fetch ISP & Country using HTTPS ipwho.is API
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
                            findings.append(
                                "🚨 **تم رصد بروكسي/VPN مشبوه:** حركة المرور تمر عبر خادم وسيط قد يُستخدم لاعتراض البيانات." if is_ar else
                                "🚨 **Proxy/VPN Detected:** Traffic is routed through an intermediary server that could intercept data."
                            )
                        if sec.get("hosting"):
                            risk_score += 20
                            findings.append(
                                "⚠️ **خادم استضافة سحابي (Hosting IP):** هذا العنوان يتبع مركز بيانات وليس شركة اتصالات تقليدية." if is_ar else
                                "⚠️ **Cloud Hosting IP:** This IP belongs to a data center rather than a standard residential/café ISP."
                            )
            except Exception:
                findings.append(
                    "ℹ️ تعذر جلب بيانات المزود الخارجي حالياً، تم الاعتماد على فحص المنافذ المباشر." if is_ar else
                    "ℹ️ External ISP lookup unavailable; proceeding with direct port security scan."
                )

            # Scan Critical Ports
            critical_ports = {
                21: ("FTP (نقل ملفات غير مشفر)", "FTP (Unencrypted File Transfer)"),
                22: ("SSH (تحكم عن بُعد)", "SSH (Remote Access)"),
                23: ("Telnet (خطير جداً - غير مشفر)", "Telnet (Critical - Unencrypted)"),
                80: ("HTTP (تصفح غير مشفر)", "HTTP (Unencrypted Web)"),
                445: ("SMB (مشاركة ملفات عرضة للاختراق)", "SMB (File Sharing Exposure)"),
                3389: ("RDP (سطح مكتب بعيد)", "RDP (Remote Desktop)"),
                8080: ("HTTP-Proxy (منفذ بروكسي مفتوح)", "HTTP-Proxy (Open Proxy Port)")
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
                if is_ar:
                    findings.append(f"🔌 **تم اكتشاف منافذ مفتوحة على الشبكة ({len(open_ports)}):**\n" + "\n".join([f"- `{p}`" for p in open_ports]))
                else:
                    findings.append(f"🔌 **Open Network Ports Detected ({len(open_ports)}):**\n" + "\n".join([f"- `{p}`" for p in open_ports]))
            else:
                findings.append(
