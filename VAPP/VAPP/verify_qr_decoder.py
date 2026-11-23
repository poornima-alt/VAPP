import cv2
import numpy as np

from qr_email_decoder import decode_qr_image

print("========== VAPP QR DECODER TEST ==========")

# Test 1: Empty input
assert decode_qr_image(b"") == []
print("TEST 1 PASSED: Empty input rejected.")

# Test 2: Oversized input
assert decode_qr_image(b"A" * (5 * 1024 * 1024 + 1)) == []
print("TEST 2 PASSED: Oversized input rejected.")

# Test 3: Invalid image
assert decode_qr_image(b"not an image") == []
print("TEST 3 PASSED: Invalid image handled.")

# Test 4: Generate a larger QR image
qr = cv2.QRCodeEncoder.create()
small_qr = qr.encode("VAPP-TEST-123")

qr_image = cv2.copyMakeBorder(
    small_qr,
    4, 4, 4, 4,
    cv2.BORDER_CONSTANT,
    value=255
)

qr_image = cv2.resize(
    qr_image,
    None,
    fx=10,
    fy=10,
    interpolation=cv2.INTER_NEAREST
)

success, encoded_image = cv2.imencode(".png", qr_image)

assert success, "QR image generation failed."

decoded = decode_qr_image(encoded_image.tobytes())

assert "VAPP-TEST-123" in decoded, (
    f"QR decoding failed. Received: {decoded}"
)

print("TEST 4 PASSED: Harmless QR payload decoded.")
print("Decoded payload:", decoded)

print("========== ALL QR TESTS PASSED ==========")