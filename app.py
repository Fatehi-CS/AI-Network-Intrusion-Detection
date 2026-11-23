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
        font-size: 2.2rem;
        font-weight: 800;
        color: #1E88E5;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        text-align: center;
        font-size: 1.05rem;
        color: #90A4AE;
        margin-bottom: 2rem;
    }
    .safe-card {
        padding: 1.5rem;
        border-radius: 12px;
        background-color: rgba(46, 125, 50, 0.15);
        border: 2px solid #2E7D32;
        margin-top: 1.5rem;
    }
    .danger-card {
        padding: 1.5rem;
        border-radius: 12px;
        background-color: rgba(198, 40, 40, 0.15);
        border: 2px solid #C62828;
        margin-top: 1.5rem;
    }
    .warn-card {
        padding: 1.5rem;
        border-radius: 12px;
        background-color: rgba(245, 124, 0, 0.15);
        border: 2px solid #F57C00;
        margin-top: 1.5rem;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar - Developer Info
with st.sidebar:
    st.image("https://icons8.com", width=75)
    st.title("The Digital Shield")
    st.markdown("**Pre-Connection Wi-Fi & IP Security Scanner (AI-NIDS)**")
    st.divider()
    st.markdown("### 👨‍💻 المطور | Developer")
    st.write("**Fatehi Abdulfattah Mohammed Ali Alshami**")
    st.markdown("🔗 [GitHub Repository](https://github.com)")
    st.divider()
    st.markdown("### 🎓 الشهادات | Certifications")
    st.info("• Cisco Junior Cybersecurity Analyst\n• Cisco Modern AI Principles")

# Main Header
st.markdown('<div class="main-title">🛡️ فاحص أمان الشبكة والـ IP</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">تأكد من أمان أي شبكة Wi-Fi في كافيه أو مكان عام عبر فحص عنوان الـ IP الخاص بها</div>', unsafe_allow_html=True)

# Input Box
ip_input = st.text_input(
    "أدخل أو الصق عنوان الـ IP الخاص بالشبكة هنا (Paste Network IP Address):",
    placeholder="مثال: 185.240.64.12  أو  8.8.8.8"
).strip()

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

# Scan Button
if st.button("🔍 افحص أمان الشبكة الآن | Scan Network IP", type="primary", use_container_width=True):
    if not ip_input:
        st.warning("⚠️ يرجى إدخال عنوان IP أولاً لبدء الفحص.")
    elif not is_valid_ip(ip_input):
        st.error("❌ صيغة عنوان الـ IP غير صحيحة! يرجى التأكد من كتابته بشكل صحيح (مثل: 185.240.12.5).")
    elif is_private_ip(ip_input):
        st.markdown(f"""
        <div class="warn-card">
            <h3>⚠️ تنبيه: هذا عنوان IP محلي داخلي ({ip_input})</h3>
            <p><b>ماذا يعني هذا؟</b> هذا عنوان الراوتر الداخلي للشبكة المحلية (Local Gateway) وليس عنوان الإنترنت العام (Public IP).</p>
            <ul>
                <li>إذا كنت في <b>كافيه أو شبكة عامة</b>: تأكد أن الشبكة محمية بكلمة مرور (WPA2/WPA3) وليست مفتوحة، ولا تقم بإدخال كلمات مرور حساباتك البنكية أو الشخصية عليها.</li>
                <li>للحصول على <b>الـ IP العام</b> للشبكة وفحصه من الخارج: افتح متصفحك واكتب <i>"What is my IP"</i> ثم انسخ الرقم الظاهر والصقه هنا.</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    else:
        with st.spinner("جاري فحص الشبكة والمنافذ المفتوحة وهوية المزود..."):
            risk_score = 0
            findings = []

            isp_name = "غير معروف (Unknown)"
            country_name = "غير معروف"

            try:
                url = f"http://ip-api.com{ip_input}?fields=status,country,isp,org,proxy,hosting"
                req = urllib.request.urlopen(url, timeout=4)
                geo_data = json.loads(req.read().decode("utf-8"))
                if geo_data.get("status") == "success":
                    isp_name = geo_data.get("isp", "Unknown")
                    country_name = geo_data.get("country", "Unknown")
                    if geo_data.get("proxy"):
                        risk_score += 40
                        findings.append("🚨 **تم رصد بروكسي/VPN مشبوه:** حركة المرور تمر عبر خادم وسيط قد يُستخدم لاعتراض البيانات.")
                    if geo_data.get("hosting"):
                        risk_score += 25
                        findings.append("⚠️ **خادم استضافة (Data Center IP):** هذا العنوان يتبع سيرفراً سحابياً وليس شركة اتصالات منزلية أو كافيه عادي.")
            except Exception:
                findings.append("ℹ️ تعذر جلب بيانات مزود الخدمة الخارجي، تم الاكتفاء بفحص المنافذ.")

            critical_ports = {
                21: "FTP (نقل ملفات غير مشفر)",
                22: "SSH (تحكم عن بُعد)",
                23: "Telnet (خطير جداً - غير مشفر)",
                80: "HTTP (تصفح غير مشفر)",
                445: "SMB (مشاركة ملفات عرضة للاختراق)",
                3389: "RDP (سطح مكتب بعيد)",
                8080: "HTTP-Proxy (منفذ بروكسي مفتوح)"
            }

            high_risk_list = (21, 23, 445, 3389)
            open_ports = []

            for port, desc in critical_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    if sock.connect_ex((ip_input, port)) == 0:
                        open_ports.append(f"Port {port}: {desc}")
                        if port in high_risk_list:
                            risk_score += 30
                        else:
                            risk_score += 15
                    sock.close()
                except Exception:
                    pass

            if open_ports:
                findings.append(f"🔌 **تم اكتشاف منافذ مفتوحة على الشبكة ({len(open_ports)}):**\n" + "\n".join([f"- `{p}`" for p in open_ports]))
            else:
                findings.append("🔒 **المنافذ الحساسة مغلقة ومحمية:** لم يتم العثور على ثغرات منافذ مكشوفة للخارج.")

            risk_score = min(risk_score, 100)

            st.divider()
            col1, col2, col3 = st.columns(3)
            col1.metric("مزود الخدمة (ISP)", isp_name[:22])
            col2.metric("الدولة (Country)", country_name)
            col3.metric("مؤشر الخطورة (Risk)", f"{risk_score}%")

            if risk_score >= 50:
                st.markdown(f"""
                <div class="danger-card">
                    <h3>🚨 تحذير خطير: هذه الشبكة غير آمنة! (نسبة الخطورة: {risk_score}%)</h3>
                    <p><b>التوصية الأمنية:</b> لا تعتمد على هذه الشبكة ولا تُدخل فيها أي بيانات شخصية أو بنكية؛ هناك منافذ خطيرة مكشوفة أو توجيه مشبوه قد يعرض جهازك للاختراق.</p>
                </div>
                """, unsafe_allow_html=True)
            elif risk_score >= 20:
                st.markdown(f"""
                <div class="warn-card">
                    <h3>⚠️ شبكة متوسطة الأمان: استخدمها بحذر (نسبة الخطورة: {risk_score}%)</h3>
                    <p><b>التوصية الأمنية:</b> الشبكة تعمل ولكن توجد بعض المنافذ المفتوحة. يُنصح بتشغيل <b>VPN</b> لحماية اتصالك أثناء التصفح.</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="safe-card">
                    <h3>✅ الشبكة آمنة ومحمية (نسبة الخطورة: {risk_score}%)</h3>
                    <p><b>التوصية الأمنية:</b> عنوان الـ IP يتبع مزود خدمة موثوق وجميع المنافذ الخطيرة مغلقة. يمكنك التصفح بأمان.</p>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("#### 📋 تفاصيل تقرير الفحص:")
            for item in findings:
                st.markdown(item)
