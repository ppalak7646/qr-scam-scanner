
import streamlit as st
import cv2
import numpy as np
import re
import tldextract

from PIL import Image
from urllib.parse import urlparse, parse_qs

st.set_page_config(
    page_title="QR Scam Scanner",
    page_icon="🔐",
    layout="centered"
)

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

                    if score >= 2:
                        st.error("Suspicious URL detected!")

                    else:
                        st.warning(
                            "No obvious warning signs detected. "
                            "This does not guarantee the website is safe."
                        )

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

                # UNKNOWN QR TYPE
                else:
                    st.warning("Unknown QR code type detected.")
                    st.write("QR Content:", qr_data)

        except Exception as error:
            st.error("Could not process this QR image.")
            st.write("Error:", str(error))
