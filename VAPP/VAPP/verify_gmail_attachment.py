
import base64
import hashlib

from gmail_monitor import get_attachment_hashes

print("========== VAPP GMAIL ATTACHMENT TEST ==========")

sample_bytes = b"VAPP harmless attachment test"
expected_hash = hashlib.sha256(sample_bytes).hexdigest()

encoded = (
    base64.urlsafe_b64encode(sample_bytes)
    .decode("ascii")
    .rstrip("=")
)

class FakeRequest:
    def __init__(self, response):
        self.response = response

    def execute(self):
        return self.response


class FakeAttachments:
    def __init__(self, response):
        self.response = response
        self.calls = 0

    def get(self, userId, messageId, id):
        self.calls += 1
        return FakeRequest(self.response)


class FakeMessages:
    def __init__(self, attachments):
        self._attachments = attachments

    def attachments(self):
        return self._attachments


class FakeUsers:
    def __init__(self, messages):
        self._messages = messages

    def messages(self):
        return self._messages


class FakeService:
    def __init__(self, response):
        self.fake_attachments = FakeAttachments(response)
        self._users = FakeUsers(
            FakeMessages(self.fake_attachments)
        )

    def users(self):
        return self._users


attachment = {
    "filename": "sample.txt",
    "mime_type": "text/plain",
    "size_bytes": len(sample_bytes),
    "attachment_id": "FAKE_ATTACHMENT_ID",
}


# Test 1: Successful download and hash
service = FakeService({"data": encoded})

results = get_attachment_hashes(
    service, "FAKE_MESSAGE_ID", [attachment]
)

assert results[0]["status"] == "hashed"
assert results[0]["sha256"] == expected_hash
assert service.fake_attachments.calls == 1

print("TEST 1 PASSED: Attachment downloaded and hash verified.")


# Test 2: Size mismatch
service = FakeService({"data": encoded})

wrong_size_attachment = {
    **attachment,
    "size_bytes": len(sample_bytes) + 5,
}

results = get_attachment_hashes(
    service, "FAKE_MESSAGE_ID", [wrong_size_attachment]
)

assert results[0]["status"] == "size_mismatch"
assert results[0]["sha256"] is None

print("TEST 2 PASSED: Incorrect attachment size rejected.")


# Test 3: Missing attachment ID
service = FakeService({"data": encoded})

missing_id_attachment = {
    **attachment,
    "attachment_id": None,
}

results = get_attachment_hashes(
    service, "FAKE_MESSAGE_ID", [missing_id_attachment]
)

assert results[0]["status"] == "no_attachment_id"
assert service.fake_attachments.calls == 0

print("TEST 3 PASSED: Missing attachment ID handled.")


# Test 4: Oversized attachment
service = FakeService({"data": encoded})

large_attachment = {
    **attachment,
    "size_bytes": 5 * 1024 * 1024 + 1,
}

results = get_attachment_hashes(
    service, "FAKE_MESSAGE_ID", [large_attachment]
)

assert results[0]["status"] == "skipped_size_limit"
assert service.fake_attachments.calls == 0

print("TEST 4 PASSED: Oversized attachment skipped.")


# Test 5: Gmail retrieval failure
class FailingRequest:
    def execute(self):
        raise RuntimeError("Simulated Gmail failure")


class FailingAttachments:
    def get(self, userId, messageId, id):
        return FailingRequest()


class FailingService:
    def users(self):
        return self

    def messages(self):
        return self

    def attachments(self):
        return FailingAttachments()


results = get_attachment_hashes(
    FailingService(), "FAKE_MESSAGE_ID", [attachment]
)

assert results[0]["status"] == "retrieval_failed"
assert results[0]["sha256"] is None

print("TEST 5 PASSED: Gmail retrieval failure handled.")

print("========== ALL GMAIL ATTACHMENT TESTS PASSED ==========")
