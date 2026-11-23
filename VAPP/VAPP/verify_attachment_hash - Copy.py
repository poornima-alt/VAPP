import hashlib

from gmail_monitor import calculate_sha256

print("========== VAPP HASH TEST ==========")

# Test 1: Known sample
sample = b"VAPP harmless attachment test"

actual = calculate_sha256(sample)
expected = hashlib.sha256(sample).hexdigest()

assert actual == expected
print("TEST 1 PASSED: SHA-256 matches expected digest.")

# Test 2: Digest length
assert len(actual) == 64
print("TEST 2 PASSED: Digest contains 64 characters.")

# Test 3: Hexadecimal format
int(actual, 16)
print("TEST 3 PASSED: Digest is valid hexadecimal.")

# Test 4: Different inputs produce different hashes
different = calculate_sha256(b"Different VAPP sample")

assert actual != different
print("TEST 4 PASSED: Different inputs produce different hashes.")

print("========== ALL HASH TESTS PASSED ==========")