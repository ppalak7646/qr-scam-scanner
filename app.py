
import csv
import io
import streamlit as st
import cv2
import numpy as np
import re
import tldextract

from PIL import Image
from urllib.parse import urlparse, parse_qs
from datetime import datetime

st.set_page_config(
    page_title="QR Scam Scanner",
    page_icon="🔐",
    layout="centered"
)
# SCAN HISTORY
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []
st.title("🔐 QR Scam Scanner")
st.write("Scan QR codes and check for suspicious links or UPI payment details.")


def extract_url(uploaded_file):
    uploaded_file.seek(0)

    pil_image = Image.open(uploaded_file).convert("RGB")
    image_array = np.array(pil_image)
    image_array = cv2.cvtColor(image_array, cv2.COLOR_RGB2BGR)

    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(image_array)

    return data if data else None


def check_url(url):
    parsed = urlparse(url)
    domain = tldextract.extract(url)

    suspicious_words = [
        "login", "verify", "account", "bank",
        "password", "update", "free", "winner"
    ]

    score = 0
    reasons = []

    if parsed.scheme.lower() != "https":
        score += 1
        reasons.append("Website does not use HTTPS")

    if len(url) > 100:
        score += 1
        reasons.append("Unusually long URL")

    if "@" in url:
        score += 2
        reasons.append("URL contains @ symbol")

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", parsed.hostname or ""):
        score += 2
        reasons.append("URL uses an IP address")

    if any(word in url.lower() for word in suspicious_words):
        score += 1
        reasons.append("Contains suspicious keywords")

    if domain.domain.count("-") >= 2:
        score += 1
        reasons.append("Domain contains multiple hyphens")

    return score, reasons


uploaded_file = st.file_uploader(
    "Upload QR Code Image",
    type=["png", "jpg", "jpeg"]
)

if uploaded_file:
    st.image(uploaded_file, caption="Uploaded QR Code", width=250)

    if st.button("Scan QR Code"):

        try:
            qr_data = extract_url(uploaded_file)

            if not qr_data:
                st.error("No QR code detected in this image.")

            else:
                st.success("QR Code successfully scanned!")

                # SAVE SCAN HISTORY
                if qr_data.lower().startswith("upi://"):
                    scan_type = "UPI"

                elif qr_data.lower().startswith(("http://", "https://")):
                    scan_type = "Website"

                elif qr_data.upper().startswith("WIFI:"):
                    scan_type = "Wi-Fi"

                elif qr_data.lower().startswith("mailto:"):
                    scan_type = "Email"

                elif qr_data.lower().startswith("tel:"):
                    scan_type = "Phone"

                else:
                    scan_type = "Other / Text"

                st.session_state.scan_history.insert(
                    0,
                    {
                        "type": scan_type,
                        "time": datetime.now().strftime(
                            "%d-%m-%Y %I:%M:%S %p"
                        )
                    }
                )

                st.session_state.scan_history = (
                    st.session_state.scan_history[:20]
                )


                # UPI QR CODE CHECK
                if qr_data.lower().startswith("upi://"):

                    st.subheader("UPI Payment QR Detected")

                    upi_data = urlparse(qr_data)
                    details = parse_qs(upi_data.query)

                    payee = details.get("pn", ["Not provided"])[0]
                    upi_id = details.get("pa", ["Not provided"])[0]
                    amount = details.get("am", ["Not specified"])[0]

                    st.write("**Payee Name:**", payee)
                    st.write("**UPI ID:**", upi_id)
                    st.write("**Amount:**", amount)

                    st.warning(
                        "UPI QR detected. This does not prove "
                        "that the recipient is genuine."
                    )

                    st.info(
                        "Verify the recipient's identity and payment "
                        "details independently. Never share your UPI PIN or OTP."
                    )

                # WEBSITE URL CHECK
                elif qr_data.lower().startswith(("http://", "https://")):

                    st.subheader("Website QR Detected")

                    st.write("**Extracted URL:**", qr_data)

                    score, reasons = check_url(qr_data)

                    st.write("**Risk indicators:**", score)

                    if score <= 1:
                        st.success("🟢 Risk Level: Low")

                    elif score <= 3:
                        st.warning("🟡 Risk Level: Medium")

                    else:
                        st.error("🔴 Risk Level: High")

                    if reasons:
                        st.write("**Reasons:**")
                        for reason in reasons:
                            st.write("- " + reason)

                    else:
                        st.write("No basic risk indicators detected.")

                    st.info(
                        "Do not enter passwords, OTPs or banking "
                        "details on an unverified website."
                    )

                
                # WIFI QR CODE DETECTION
                elif qr_data.startswith("WIFI:"):
                    st.subheader("Wi-Fi QR Code Detected")

                    wifi_data = {}

                    raw_data = qr_data[5:].rstrip(";")

                    for item in raw_data.split(";"):
                        if ":" in item:
                            key, value = item.split(":", 1)
                            wifi_data[key] = value

                    ssid = wifi_data.get("S", "Unknown")
                    security = wifi_data.get("T", "Unknown")
                    password = wifi_data.get("P", "")

                    st.success("Wi-Fi QR code successfully detected!")

                    st.write("**Network Name:**", ssid)
                    st.write("**Security Type:**", security)

                    if password:
                        if st.checkbox("Show Wi-Fi password"):
                            st.code(password)
                        else:
                            st.info("Wi-Fi password is hidden.")
                    else:
                        st.info("No password found in this QR code.")

                
                # EMAIL QR CODE DETECTION
                elif qr_data.lower().startswith("mailto:"):
                    st.subheader("Email QR Code Detected")

                    email_data = urlparse(qr_data)
                    email_address = email_data.path

                    email_details = parse_qs(email_data.query)
                    subject = email_details.get("subject", [""])[0]

                    st.success("Email QR code successfully detected!")
                    st.write("**Email Address:**", email_address)

                    if subject:
                        st.write("**Subject:**", subject)

                    st.info(
                        "Check the email address carefully before "
                        "sending any message."
                    )

                # PHONE QR CODE DETECTION
                elif qr_data.lower().startswith("tel:"):
                    st.subheader("Phone QR Code Detected")

                    phone_number = qr_data[4:].split("?")[0]

                    st.success("Phone QR code successfully detected!")
                    st.write("**Phone Number:**", phone_number)

                    st.info(
                        "Verify the number before making a call. "
                        "This scanner will not place calls automatically."
                    )



        except Exception as error:
            st.error("Could not process this QR image.")
            st.write("Error:", str(error))


# SCAN HISTORY DISPLAY
st.divider()
st.subheader("📋 QR Scan History")

if st.session_state.scan_history:

    for index, item in enumerate(st.session_state.scan_history, 1):
        st.write(
            f"**{index}. {item['type']}** — {item['time']}"
        )
            # DOWNLOAD SCAN REPORT
    csv_buffer = io.StringIO()

    csv_writer = csv.DictWriter(
        csv_buffer,
        fieldnames=["type", "time"]
    )

    csv_writer.writeheader()
    csv_writer.writerows(st.session_state.scan_history)

    st.download_button(
        label="⬇️ Download Scan Report",
        data=csv_buffer.getvalue(),
        file_name="qr_scan_history.csv",
        mime="text/csv"
    )

    if st.button("🗑️ Clear History"):
        st.session_state.scan_history = []
        st.rerun()

else:
    st.info("No scan history available yet.")
