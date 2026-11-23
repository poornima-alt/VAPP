import cv2
import numpy as np

def decode_qr_image(image_bytes):
    """Decode QR payloads from image bytes without opening any URLs."""
    if not image_bytes or len(image_bytes) > 5 * 1024 * 1024:
        return []

    try:
        encoded = np.frombuffer(image_bytes, dtype=np.uint8)
        image = cv2.imdecode(encoded, cv2.IMREAD_COLOR)
        if image is None:
            return []

        detector = cv2.QRCodeDetector()
        payloads = []

        ok, decoded, points, _ = detector.detectAndDecodeMulti(image)
        if ok:
            payloads.extend(value for value in decoded if value)

        if not payloads:
            value, points, _ = detector.detectAndDecode(image)
            if value:
                payloads.append(value)

        return list(dict.fromkeys(payloads))
    except Exception:
        return []
