# Mock RP regression tests: signed wire protocol, enroll, rotation 3-phase, recovery, step-up, backup, simulators
import base64
import hashlib
import hmac
import json
import os
import time
import uuid

import pytest
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

BASE_URL = os.environ.get("EXPO_PUBLIC_BACKEND_URL", os.environ.get("EXPO_BACKEND_URL")).rstrip("/")
API = f"{BASE_URL}/api"
WK = f"{API}/.well-known/credential-agent"
DOMAIN = "test-example.com"


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def jwk(key):
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}


def sign(key, data):
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def verifier(seed: bytes):
    return "pbkdf2-sha256$1000$" + hashlib.sha256(seed).hexdigest()


def proof(ver, domain, rid, phase, ts):
    return hmac.new(bytes.fromhex(ver.split("$")[2]), f"{domain}|{rid}|{phase}|{ts}".encode(), hashlib.sha256).hexdigest()


class Agent:
    def __init__(self):
        self.id = "TEST_" + uuid.uuid4().hex
        self.ik = ec.generate_private_key(ec.SECP256R1())
        self.dk = ec.generate_private_key(ec.SECP256R1())

    def post(self, path, body, key=None, raw=None, headers=None, method="post"):
        data = raw if raw is not None else canon(body)
        h = {"Content-Type": "application/json", "X-Agent-Id": self.id, "X-Agent-Signature": sign(key or self.dk, data)}
        if headers is not None:
            h = headers
        return requests.request(method, path, data=data, headers=h, timeout=20)


def rp_pub():
    j = requests.get(f"{WK}/rp-key", timeout=20).json()
    x, y = int.from_bytes(b64d(j["x"]), "big"), int.from_bytes(b64d(j["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(), j


def assert_rp_signed(resp):
    pub, _ = rp_pub()
    sig = b64d(resp.headers["X-RP-Signature"])
    pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), resp.content, ec.ECDSA(hashes.SHA256()))


@pytest.fixture(scope="module")
def agent():
    a = Agent()
    r = a.post(f"{WK}/agent/register", {"agentId": a.id, "publicKeyJwk": jwk(a.ik), "timestamp": int(time.time())}, key=a.ik)
    assert r.status_code == 200, r.text
    assert r.json()["result"] == "REGISTERED"
    assert_rp_signed(r)
    a.v0 = verifier(b"v0")
    r = a.post(f"{WK}/enroll", {"domain": DOMAIN, "publicKeyJwk": jwk(a.dk), "initialPasswordHash": a.v0,
                                "trustedDevices": ["this-pc"], "timestamp": int(time.time())})
    assert r.status_code == 200, r.text
    assert r.json()["result"] == "ENROLLED"
    return a


class TestKeyAndRegister:
    def test_rp_key(self):
        _, j = rp_pub()
        assert j["kty"] == "EC" and j["crv"] == "P-256" and j["allowSimulatedUV"] is True

    def test_register_idempotent(self, agent):
        r = agent.post(f"{WK}/agent/register", {"agentId": agent.id, "publicKeyJwk": jwk(agent.ik), "timestamp": int(time.time())}, key=agent.ik)
        assert r.status_code == 200 and r.json()["result"] == "ALREADY_REGISTERED"

    def test_account_view_after_enroll(self, agent):
        j = requests.get(f"{API}/rp/accounts/{agent.id}/{DOMAIN}", timeout=20).json()
        assert j["activeFingerprint"] == agent.v0.split("$")[2][:12]
        ids = {s["deviceId"]: s for s in j["sessions"]}
        assert ids["this-pc"]["trusted"] and not ids["unknown-chromebook-7f3a"]["trusted"]


class TestRejects:
    def body(self):
        return {"domain": DOMAIN, "rotationId": "r", "phase": "PROBE", "candidatePasswordProof": "x", "purgePreviousSlot": False, "timestamp": int(time.time())}

    def test_unsigned(self, agent):
        r = agent.post(f"{WK}/rotate-verify", self.body(), headers={"Content-Type": "application/json"})
        assert r.status_code == 401 and r.json()["error"] == "MISSING_SIGNATURE"
        assert_rp_signed(r)

    def test_bad_signature(self, agent):
        r = agent.post(f"{WK}/rotate-verify", self.body(), key=agent.ik)  # wrong key
        assert r.status_code == 401 and r.json()["error"] == "BAD_AGENT_SIGNATURE"

    def test_non_canonical(self, agent):
        raw = json.dumps(self.body(), indent=1).encode()
        r = agent.post(f"{WK}/rotate-verify", None, raw=raw)
        assert r.status_code == 400 and r.json()["error"] == "NON_CANONICAL"

    def test_extra_field(self, agent):
        b = self.body(); b["evil"] = 1
        r = agent.post(f"{WK}/rotate-verify", b)
        assert r.status_code == 422 and r.json()["error"] == "SCHEMA_VIOLATION"

    def test_stale_timestamp(self, agent):
        b = self.body(); b["timestamp"] = int(time.time()) - 3600
        r = agent.post(f"{WK}/rotate-verify", b)
        assert r.status_code == 400 and r.json()["error"] == "STALE_TIMESTAMP"

    def test_userverified_true_rejected(self, agent):
        r = agent.post(f"{WK}/rotate-stage", {"domain": DOMAIN, "rotationId": "x", "stagedPasswordHash": verifier(b"z"),
                                              "preserveTrustedSessions": [], "userVerified": True, "timestamp": int(time.time())})
        assert r.status_code == 400 and r.json()["error"] == "TIER_MISMATCH"


class TestRotation:
    def test_full_rotation_cycle(self, agent):
        rid, v1 = str(uuid.uuid4()), verifier(b"v1")
        r = agent.post(f"{WK}/rotate-stage", {"domain": DOMAIN, "rotationId": rid, "stagedPasswordHash": v1,
                                              "preserveTrustedSessions": ["this-pc"], "userVerified": False, "timestamp": int(time.time())})
        assert r.status_code == 200 and r.json()["result"] == "STAGED"

        def verify(phase, ver, purge=False):
            ts = int(time.time())
            return agent.post(f"{WK}/rotate-verify", {"domain": DOMAIN, "rotationId": rid, "phase": phase,
                                                      "candidatePasswordProof": proof(ver, DOMAIN, rid, phase, ts), "purgePreviousSlot": purge, "timestamp": ts})
        assert verify("PROBE", v1).json()["matchedSlot"] == "STAGED"
        assert verify("PROBE", agent.v0).json()["matchedSlot"] == "ACTIVE"
        r = verify("VERIFY_AND_COMMIT", v1)
        j = r.json()
        assert j["result"] == "COMMITTED" and "unknown-chromebook-7f3a" in j["revokedSessions"] and "this-pc" in j["preservedSessions"]
        assert verify("VERIFY_AND_COMMIT", v1).json()["result"] == "ALREADY_COMMITTED"  # idempotent
        acct = requests.get(f"{API}/rp/accounts/{agent.id}/{DOMAIN}", timeout=20).json()
        assert acct["rotations"] == 1 and acct["previousSlotPresent"] and acct["stagedFingerprint"] is None
        assert verify("ACK_PURGE", v1).json()["result"] == "PURGED"
        assert requests.get(f"{API}/rp/accounts/{agent.id}/{DOMAIN}", timeout=20).json()["previousSlotPresent"] is False
        bad = verify("VERIFY_AND_COMMIT", verifier(b"wrong"))
        assert bad.status_code == 409 and bad.json()["error"] == "PROOF_REJECTED"


class TestRecoveryAndStepUp:
    def test_untrusted_reset_auto_reject(self, agent):
        s = requests.post(f"{API}/rp/simulate/reset-request", json={"agentId": agent.id, "domain": DOMAIN, "deviceId": "evil", "originIp": "203.0.113.9"}, timeout=20).json()
        assert s["kind"] == "RESET"
        body = {"domain": DOMAIN, "challengeId": s["challengeId"], "requestOriginIp": "203.0.113.9", "isTrustedDevice": False,
                "action": "AUTO_REJECT_UNAUTHORIZED_RESET", "timestamp": int(time.time())}
        r = agent.post(f"{WK}/recovery-challenge", body)
        assert r.status_code == 200 and r.json()["result"] == "REJECTED"
        body["timestamp"] = int(time.time())
        assert agent.post(f"{WK}/recovery-challenge", body).status_code == 409

    def _step(self, agent, action, device="this-pc"):
        s = requests.post(f"{API}/rp/simulate/step-up-request", json={"agentId": agent.id, "domain": DOMAIN, "actionType": action,
                          "humanReadableContext": "TEST", "requestingDevice": device, "requestOriginIp": "10.0.0.2"}, timeout=20).json()
        return s

    def test_pairing_approve_simulated(self, agent):
        s = self._step(agent, "AUTHORIZE_NEW_DEVICE_PAIRING", device="TEST_macbook")
        pend = requests.get(f"{API}/rp/pending", params={"agentId": agent.id}, timeout=20).json()["challenges"]
        assert any(c["challengeId"] == s["challengeId"] for c in pend)
        r = agent.post(f"{WK}/step-up", {"domain": DOMAIN, "challengeId": s["challengeId"], "actionType": "AUTHORIZE_NEW_DEVICE_PAIRING",
                                         "humanReadableContext": "TEST", "payloadSha256": s["payloadSha256"], "requireUserVerification": True,
                                         "decision": "APPROVE", "assertion": {"simulated": True}, "timestamp": int(time.time())})
        assert r.status_code == 200 and r.json()["uvSource"] == "simulated"
        sess = requests.get(f"{API}/rp/accounts/{agent.id}/{DOMAIN}", timeout=20).json()["sessions"]
        assert any(x["deviceId"] == "TEST_macbook" and x["trusted"] for x in sess)

    def test_step_up_payload_mismatch_and_deny(self, agent):
        s = self._step(agent, "TRANSFER_OWNERSHIP")
        base = {"domain": DOMAIN, "challengeId": s["challengeId"], "actionType": "TRANSFER_OWNERSHIP", "humanReadableContext": "TEST",
                "payloadSha256": "00" * 32, "requireUserVerification": True, "decision": "APPROVE", "assertion": {"simulated": True}, "timestamp": int(time.time())}
        assert agent.post(f"{WK}/step-up", base).json()["error"] == "PAYLOAD_MISMATCH"
        base.update(payloadSha256=s["payloadSha256"], decision="DENY", assertion=None)
        assert agent.post(f"{WK}/step-up", base).json()["result"] == "DENIED"

    def test_step_up_requires_assertion(self, agent):
        s = self._step(agent, "TRANSFER_OWNERSHIP")
        r = agent.post(f"{WK}/step-up", {"domain": DOMAIN, "challengeId": s["challengeId"], "actionType": "TRANSFER_OWNERSHIP", "humanReadableContext": "TEST",
                                         "payloadSha256": s["payloadSha256"], "requireUserVerification": True, "decision": "APPROVE", "timestamp": int(time.time())})
        assert r.status_code == 401 and r.json()["error"] == "UV_REQUIRED"


class TestBackup:
    def test_backup_flow(self, agent):
        bid = "TEST_" + uuid.uuid4().hex
        ct = b"ciphertext-bytes"
        sha = hashlib.sha256(ct).hexdigest()
        body = {"agentId": agent.id, "backupId": bid, "iv": b64u(b"iv" * 6), "ciphertext": b64u(ct), "ciphertextSha256": sha,
                "mode": "TIER1_SYNC", "timestamp": int(time.time())}
        r = agent.post(f"{API}/backup", body, key=agent.ik, method="put")
        assert r.status_code == 403 and r.json()["error"] == "SYNC_NOT_AUTHORIZED"
        body.update(mode="TIER2_EXPORT", assertion={"simulated": True})
        r = agent.post(f"{API}/backup", body, key=agent.ik, method="put")
        assert r.status_code == 200 and r.json()["result"] == "STORED"
        body.update(mode="TIER1_SYNC"); body.pop("assertion")
        assert agent.post(f"{API}/backup", body, key=agent.ik, method="put").status_code == 200
        g = requests.get(f"{API}/backup/{bid}", timeout=20)
        assert g.status_code == 200 and g.json()["ciphertextSha256"] == sha and "agentId" not in g.json()
        assert_rp_signed(g)
        body["ciphertextSha256"] = "00" * 32
        assert agent.post(f"{API}/backup", body, key=agent.ik, method="put").json()["error"] == "HASH_MISMATCH"

    def test_backup_missing(self):
        assert requests.get(f"{API}/backup/TEST_nonexistent", timeout=20).status_code == 404
