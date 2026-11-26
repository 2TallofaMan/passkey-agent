"""Mock Relying Party server for the deterministic Credential & Passkey Agent.

All /.well-known/credential-agent/* requests must be canonical JSON signed with the
agent's domain-scoped (or agent-identity) P-256 key in `X-Agent-Signature` (raw r||s,
base64url). Every response is canonical JSON signed by the RP key in `X-RP-Signature`.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Any, List, Literal, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from dotenv import load_dotenv
from fastapi import APIRouter, FastAPI, Query, Request
from fastapi.responses import Response
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, ConfigDict, ValidationError
from datetime import datetime, timezone

from pymongo import ASCENDING, IndexModel
from pymongo.errors import DuplicateKeyError

from aws_connector import dependent_loop, make_router as make_aws_router
from docs_content import DOCS
from pdfs import render_pdf
from starlette.middleware.cors import CORSMiddleware

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]
ALLOW_SIMULATED_UV = os.environ.get("ALLOW_SIMULATED_UV", "false").lower() == "true"
MAX_SKEW = 600
WK = "/.well-known/credential-agent"

logger = logging.getLogger("mock-rp")
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

INDEXES: dict[str, list[IndexModel]] = {
    "rp_agents": [IndexModel([("agentId", ASCENDING)], name="agentId", unique=True)],
    "rp_accounts": [IndexModel([("agentId", ASCENDING), ("domain", ASCENDING)], name="agent_domain", unique=True)],
    "rp_challenges": [
        IndexModel([("challengeId", ASCENDING)], name="challengeId", unique=True),
        IndexModel([("agentId", ASCENDING), ("status", ASCENDING)], name="agent_status"),
    ],
    "rp_backups": [IndexModel([("backupId", ASCENDING)], name="backupId", unique=True)],
    "rp_replay": [
        IndexModel([("sigHash", ASCENDING)], name="sigHash", unique=True),
        IndexModel([("createdAt", ASCENDING)], name="ttl", expireAfterSeconds=MAX_SKEW * 2),
    ],
}


async def ensure_indexes() -> None:
    for collection, models in INDEXES.items():
        for model in models:
            try:
                await db[collection].create_indexes([model])
            except Exception as exc:
                logger.error("ensure_indexes(%s.%s): %s", collection, model.document["name"], exc)


# ---------------------------------------------------------------- helpers
def b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def now() -> int:
    return int(time.time())


class RpErr(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message


_rp_key: Optional[ec.EllipticCurvePrivateKey] = None


async def rp_key() -> ec.EllipticCurvePrivateKey:
    global _rp_key
    if _rp_key is None:
        doc = await db.rp_config.find_one({"name": "rp_signing_key"}, {"_id": 0})
        if doc:
            _rp_key = serialization.load_pem_private_key(doc["pem"].encode(), password=None)
        else:
            key = ec.generate_private_key(ec.SECP256R1())
            pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
            await db.rp_config.update_one({"name": "rp_signing_key"}, {"$setOnInsert": {"pem": pem}}, upsert=True)
            doc = await db.rp_config.find_one({"name": "rp_signing_key"}, {"_id": 0})
            _rp_key = serialization.load_pem_private_key(doc["pem"].encode(), password=None)
    return _rp_key


async def signed(data: dict, status: int = 200) -> Response:
    body = canonical(data)
    der = (await rp_key()).sign(body, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    sig = b64u_enc(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return Response(body, status_code=status, media_type="application/json", headers={"X-RP-Signature": sig})


def jwk_pub(jwk: dict) -> ec.EllipticCurvePublicKey:
    x = int.from_bytes(b64u_dec(jwk["x"]), "big")
    y = int.from_bytes(b64u_dec(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def verify_raw(jwk: dict, sig_b64: str, data: bytes) -> None:
    try:
        sig = b64u_dec(sig_b64)
        if len(sig) != 64:
            raise ValueError("bad length")
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        jwk_pub(jwk).verify(der, data, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, KeyError) as exc:
        raise RpErr(401, "BAD_AGENT_SIGNATURE", f"X-Agent-Signature verification failed: {exc.__class__.__name__}")


async def read_signed(request: Request, model: type[BaseModel]):
    raw = await request.body()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        raise RpErr(400, "BAD_JSON", "Body is not JSON")
    if canonical(parsed) != raw:
        raise RpErr(400, "NON_CANONICAL", "Body must be canonical JSON (sorted keys, no whitespace)")
    try:
        body = model.model_validate(parsed)
    except ValidationError as exc:
        raise RpErr(422, "SCHEMA_VIOLATION", exc.errors()[0]["msg"] + " @ " + ".".join(str(p) for p in exc.errors()[0]["loc"]))
    if abs(now() - getattr(body, "timestamp", 0)) > MAX_SKEW:
        raise RpErr(400, "STALE_TIMESTAMP", "Timestamp outside the allowed window")
    agent_id = request.headers.get("X-Agent-Id")
    sig = request.headers.get("X-Agent-Signature")
    if not agent_id or not sig:
        raise RpErr(401, "MISSING_SIGNATURE", "X-Agent-Id and X-Agent-Signature are required")
    domain = parsed.get("domain") if isinstance(parsed, dict) else None
    if domain and await db.svc_status.find_one({"domain": domain, "outage": True}):
        raise RpErr(503, "SERVICE_OUTAGE", f"{domain} is offline")
    # Replay blocking: a given signed request can be accepted only once.
    try:
        await db.rp_replay.insert_one({"sigHash": hashlib.sha256(sig.encode() + raw).hexdigest(), "createdAt": datetime.now(timezone.utc)})
    except DuplicateKeyError:
        raise RpErr(409, "REPLAY_BLOCKED", "This signed request was already used")
    return body, parsed, agent_id, sig, raw


async def load_agent(agent_id: str) -> dict:
    agent = await db.rp_agents.find_one({"agentId": agent_id}, {"_id": 0})
    if not agent:
        raise RpErr(404, "UNKNOWN_AGENT", "Agent is not registered")
    return agent


async def load_account(agent_id: str, domain: str, sig: str, raw: bytes) -> dict:
    acct = await db.rp_accounts.find_one({"agentId": agent_id, "domain": domain}, {"_id": 0})
    if not acct:
        raise RpErr(404, "UNKNOWN_ACCOUNT", f"No enrolled account for {domain}")
    verify_raw(acct["publicJwk"], sig, raw)
    return acct


def verifier_bytes(v: Optional[str]) -> Optional[bytes]:
    if not v:
        return None
    parts = v.split("$")
    if len(parts) != 3 or parts[0] != "pbkdf2-sha256":
        raise RpErr(422, "BAD_HASH_FORMAT", "Expected pbkdf2-sha256$<iterations>$<hex>")
    return bytes.fromhex(parts[2])


def proof_ok(verifier: Optional[str], domain: str, rotation_id: str, phase: str, ts: int, proof: str) -> bool:
    key = verifier_bytes(verifier)
    if key is None:
        return False
    expected = hmac.new(key, f"{domain}|{rotation_id}|{phase}|{ts}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, proof)


def fp(verifier: Optional[str]) -> Optional[str]:
    return verifier.split("$")[2][:12] if verifier else None


def verify_webauthn(agent: dict, assertion: Optional[dict], challenge: bytes) -> str:
    if not assertion:
        raise RpErr(401, "UV_REQUIRED", "User verification assertion required")
    if assertion.get("simulated") is True:
        if ALLOW_SIMULATED_UV:
            return "simulated"
        raise RpErr(401, "SIMULATED_UV_DISABLED", "Simulated approvals are disabled on this RP")
    t2 = agent.get("tier2")
    if not t2:
        raise RpErr(412, "TIER2_NOT_ENROLLED", "No Windows Hello credential enrolled")
    try:
        if assertion["credentialId"] != t2["credentialId"]:
            raise RpErr(401, "WRONG_CREDENTIAL", "Assertion from an unknown credential")
        cd_raw = b64u_dec(assertion["clientDataJSON"])
        cd = json.loads(cd_raw)
        auth = b64u_dec(assertion["authenticatorData"])
        sig = b64u_dec(assertion["signature"])
    except (KeyError, ValueError):
        raise RpErr(422, "BAD_ASSERTION", "Malformed WebAuthn assertion")
    if cd.get("type") != "webauthn.get":
        raise RpErr(401, "BAD_ASSERTION", "clientData.type must be webauthn.get")
    if cd.get("challenge") != b64u_enc(challenge):
        raise RpErr(401, "CHALLENGE_MISMATCH", "Assertion is not bound to this payload hash")
    if auth[:32] != hashlib.sha256(t2["rpId"].encode()).digest():
        raise RpErr(401, "RPID_MISMATCH", "rpIdHash mismatch")
    flags = auth[32]
    if not (flags & 0x01) or not (flags & 0x04):
        raise RpErr(401, "UV_FLAG_MISSING", "Authenticator did not assert user presence + verification")
    pub = serialization.load_der_public_key(b64u_dec(t2["spki"]))
    data = auth + hashlib.sha256(cd_raw).digest()
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise RpErr(422, "UNSUPPORTED_ALG", "Unsupported credential algorithm")
    except InvalidSignature:
        raise RpErr(401, "BAD_UV_SIGNATURE", "Hardware signature invalid")
    return "hardware"


# ---------------------------------------------------------------- wire schemas
class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Jwk(Strict):
    kty: Literal["EC"]
    crv: Literal["P-256"]
    x: str
    y: str


class AgentRegister(Strict):
    agentId: str
    publicKeyJwk: Jwk
    timestamp: int


class Tier2Register(Strict):
    agentId: str
    credentialId: str
    spki: str
    alg: int
    rpId: str
    timestamp: int


class Enroll(Strict):
    domain: str
    username: str
    publicKeyJwk: Jwk
    initialPasswordHash: str
    trustedDevices: List[str]
    timestamp: int


class RotateStage(Strict):
    domain: str
    rotationId: str
    stagedPasswordHash: str
    preserveTrustedSessions: List[str]
    userVerified: bool
    timestamp: int


class RotateVerify(Strict):
    domain: str
    rotationId: str
    phase: Literal["VERIFY_AND_COMMIT", "PROBE", "ACK_PURGE"]
    candidatePasswordProof: str
    purgePreviousSlot: bool
    timestamp: int


class RecoveryChallenge(Strict):
    domain: str
    challengeId: str
    requestOriginIp: str
    isTrustedDevice: bool
    action: Literal["AUTO_REJECT_UNAUTHORIZED_RESET"]
    timestamp: int


class StepUp(Strict):
    domain: str
    challengeId: str
    actionType: str
    humanReadableContext: str
    payloadSha256: str
    requireUserVerification: bool
    decision: Literal["APPROVE", "DENY"]
    assertion: Optional[dict] = None
    timestamp: int


class BackupPut(Strict):
    agentId: str
    backupId: str
    iv: str
    ciphertext: str
    ciphertextSha256: str
    mode: Literal["TIER2_EXPORT", "TIER1_SYNC"]
    assertion: Optional[dict] = None
    timestamp: int


class SimReset(BaseModel):
    agentId: str
    domain: str
    deviceId: str
    originIp: str


class SimStepUp(BaseModel):
    agentId: str
    domain: str
    actionType: str
    humanReadableContext: str
    requestingDevice: str
    requestOriginIp: str


class SimSession(BaseModel):
    agentId: str
    domain: str
    deviceId: str


# ---------------------------------------------------------------- app
app = FastAPI(title="Mock Relying Party")


@app.exception_handler(RpErr)
async def rp_err_handler(_: Request, exc: RpErr):
    return await signed({"error": exc.code, "message": exc.message}, exc.status)


@app.get("/health", include_in_schema=False)
@app.head("/health", include_in_schema=False)
async def health():
    return {"status": "ok"}


api = APIRouter(prefix="/api")


@api.get("/")
async def root():
    return {"service": "mock-relying-party", "allowSimulatedUV": ALLOW_SIMULATED_UV}


@api.get(WK + "/rp-key")
async def get_rp_key():
    nums = (await rp_key()).public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "x": b64u_enc(nums.x.to_bytes(32, "big")), "y": b64u_enc(nums.y.to_bytes(32, "big"))}
    return {**jwk, "allowSimulatedUV": ALLOW_SIMULATED_UV}


@api.post(WK + "/agent/register")
async def agent_register(request: Request):
    body, _, agent_id, sig, raw = await read_signed(request, AgentRegister)
    if agent_id != body.agentId:
        raise RpErr(400, "AGENT_MISMATCH", "Header/body agentId mismatch")
    jwk = body.publicKeyJwk.model_dump()
    verify_raw(jwk, sig, raw)
    existing = await db.rp_agents.find_one({"agentId": agent_id}, {"_id": 0})
    if existing and existing["publicJwk"] != jwk:
        raise RpErr(409, "AGENT_KEY_CONFLICT", "Agent already registered with a different key")
    if not existing:
        await db.rp_agents.insert_one({"agentId": agent_id, "publicJwk": jwk, "tier2": None, "backupSyncEnabled": False, "createdAt": now()})
    return await signed({"result": "REGISTERED" if not existing else "ALREADY_REGISTERED", "agentId": agent_id})


@api.post(WK + "/tier2/register")
async def tier2_register(request: Request):
    body, _, agent_id, sig, raw = await read_signed(request, Tier2Register)
    agent = await load_agent(agent_id)
    verify_raw(agent["publicJwk"], sig, raw)
    try:
        serialization.load_der_public_key(b64u_dec(body.spki))
    except ValueError:
        raise RpErr(422, "BAD_SPKI", "Invalid public key")
    t2 = {"credentialId": body.credentialId, "spki": body.spki, "alg": body.alg, "rpId": body.rpId, "registeredAt": now()}
    await db.rp_agents.update_one({"agentId": agent_id}, {"$set": {"tier2": t2}})
    return await signed({"result": "TIER2_ENROLLED", "credentialId": body.credentialId})


@api.post(WK + "/enroll")
async def enroll(request: Request):
    body, _, agent_id, sig, raw = await read_signed(request, Enroll)
    await load_agent(agent_id)
    jwk = body.publicKeyJwk.model_dump()
    verify_raw(jwk, sig, raw)
    verifier_bytes(body.initialPasswordHash)
    existing = await db.rp_accounts.find_one({"agentId": agent_id, "domain": body.domain}, {"_id": 0})
    if existing and existing["publicJwk"] != jwk:
        raise RpErr(409, "ACCOUNT_KEY_CONFLICT", "Domain enrolled with a different key")
    sessions = [{"deviceId": d, "trusted": True, "revoked": False, "createdAt": now()} for d in body.trustedDevices]
    sessions.append({"deviceId": "unknown-chromebook-7f3a", "trusted": False, "revoked": False, "createdAt": now()})
    doc = {
        "agentId": agent_id, "domain": body.domain, "username": body.username, "publicJwk": jwk, "passwordChangedAt": now(),
        "activeVerifier": body.initialPasswordHash, "previousVerifier": None, "stagedVerifier": None,
        "stagedRotationId": None, "lastCommittedRotationId": None, "preserve": body.trustedDevices,
        "sessions": sessions, "rotations": 0, "updatedAt": now(),
    }
    await db.rp_accounts.replace_one({"agentId": agent_id, "domain": body.domain}, doc, upsert=True)
    return await signed({"result": "ENROLLED", "domain": body.domain, "activeFingerprint": fp(body.initialPasswordHash)})


@api.post(WK + "/rotate-stage")
async def rotate_stage(request: Request):
    body, _, agent_id, sig, raw = await read_signed(request, RotateStage)
    acct = await load_account(agent_id, body.domain, sig, raw)
    verifier_bytes(body.stagedPasswordHash)
    if body.userVerified:
        raise RpErr(400, "TIER_MISMATCH", "Tier 1 rotations must be userVerified=false")
    await db.rp_accounts.update_one(
        {"agentId": agent_id, "domain": acct["domain"]},
        {"$set": {"stagedVerifier": body.stagedPasswordHash, "stagedRotationId": body.rotationId, "preserve": body.preserveTrustedSessions, "updatedAt": now()}},
    )
    return await signed({"result": "STAGED", "domain": body.domain, "rotationId": body.rotationId, "stagedFingerprint": fp(body.stagedPasswordHash)})


@api.post(WK + "/rotate-verify")
async def rotate_verify(request: Request):
    body, _, agent_id, sig, raw = await read_signed(request, RotateVerify)
    acct = await load_account(agent_id, body.domain, sig, raw)
    q = {"agentId": agent_id, "domain": body.domain}

    def ok(v):
        return proof_ok(v, body.domain, body.rotationId, body.phase, body.timestamp, body.candidatePasswordProof)

    if body.phase == "PROBE":
        slot = "ACTIVE" if ok(acct["activeVerifier"]) else "STAGED" if ok(acct["stagedVerifier"]) else "NONE"
        return await signed({"result": "PROBED", "matchedSlot": slot, "domain": body.domain, "activeFingerprint": fp(acct["activeVerifier"])})

    if body.phase == "ACK_PURGE":
        if acct["lastCommittedRotationId"] != body.rotationId or not ok(acct["activeVerifier"]):
            raise RpErr(409, "ACK_REJECTED", "ACK does not match the committed rotation")
        await db.rp_accounts.update_one(q, {"$set": {"previousVerifier": None, "updatedAt": now()}})
        return await signed({"result": "PURGED", "domain": body.domain, "rotationId": body.rotationId})

    if acct["stagedVerifier"] and acct["stagedRotationId"] == body.rotationId and ok(acct["stagedVerifier"]):
        preserve = set(acct.get("preserve") or [])
        revoked, preserved = [], []
        for s in acct["sessions"]:
            if s["revoked"]:
                continue
            if s["deviceId"] in preserve:
                s["trusted"] = True
                preserved.append(s["deviceId"])
            else:
                s["revoked"] = True
                s["revokedAt"] = now()
                revoked.append(s["deviceId"])
        await db.rp_accounts.update_one(q, {"$set": {
            "previousVerifier": None if body.purgePreviousSlot else acct["activeVerifier"],
            "activeVerifier": acct["stagedVerifier"], "stagedVerifier": None, "stagedRotationId": None,
            "lastCommittedRotationId": body.rotationId, "sessions": acct["sessions"], "passwordChangedAt": now(),
            "rotations": acct.get("rotations", 0) + 1, "updatedAt": now(),
        }})
        return await signed({"result": "COMMITTED", "domain": body.domain, "rotationId": body.rotationId,
                             "activeFingerprint": fp(acct["stagedVerifier"]), "preservedSessions": preserved, "revokedSessions": revoked})
    if acct["lastCommittedRotationId"] == body.rotationId and ok(acct["activeVerifier"]):
        return await signed({"result": "ALREADY_COMMITTED", "domain": body.domain, "rotationId": body.rotationId,
                             "activeFingerprint": fp(acct["activeVerifier"]), "preservedSessions": [], "revokedSessions": []})
    raise RpErr(409, "PROOF_REJECTED", "Candidate password proof does not match a staged or committed slot")


@api.post(WK + "/recovery-challenge")
async def recovery_challenge(request: Request):
    body, _, agent_id, sig, raw = await read_signed(request, RecoveryChallenge)
    await load_account(agent_id, body.domain, sig, raw)
    ch = await db.rp_challenges.find_one({"challengeId": body.challengeId, "agentId": agent_id, "kind": "RESET"}, {"_id": 0})
    if not ch:
        raise RpErr(404, "UNKNOWN_CHALLENGE", "No such reset challenge")
    if ch["status"] != "PENDING":
        raise RpErr(409, "ALREADY_RESOLVED", f"Challenge already {ch['status']}")
    if ch["isTrustedDevice"] != body.isTrustedDevice or ch["requestOriginIp"] != body.requestOriginIp:
        raise RpErr(400, "CONTEXT_MISMATCH", "Challenge context mismatch")
    await db.rp_challenges.update_one({"challengeId": body.challengeId}, {"$set": {"status": "AUTO_REJECTED", "resolvedAt": now()}})
    return await signed({"result": "REJECTED", "challengeId": body.challengeId, "domain": body.domain})


@api.post(WK + "/step-up")
async def step_up(request: Request):
    body, _, agent_id, sig, raw = await read_signed(request, StepUp)
    acct = await load_account(agent_id, body.domain, sig, raw)
    agent = await load_agent(agent_id)
    ch = await db.rp_challenges.find_one({"challengeId": body.challengeId, "agentId": agent_id, "kind": "STEP_UP"}, {"_id": 0})
    if not ch:
        raise RpErr(404, "UNKNOWN_CHALLENGE", "No such step-up challenge")
    if ch["status"] != "PENDING":
        raise RpErr(409, "ALREADY_RESOLVED", f"Challenge already {ch['status']}")
    if body.payloadSha256 != ch["payloadSha256"] or body.actionType != ch["payload"]["actionType"]:
        raise RpErr(400, "PAYLOAD_MISMATCH", "Payload hash does not match the issued challenge")
    if body.decision == "DENY":
        await db.rp_challenges.update_one({"challengeId": body.challengeId}, {"$set": {"status": "DENIED", "resolvedAt": now()}})
        return await signed({"result": "DENIED", "challengeId": body.challengeId})
    uv = verify_webauthn(agent, body.assertion, bytes.fromhex(ch["payloadSha256"]))
    extra: dict = {}
    if ch["payload"]["actionType"] == "AUTHORIZE_NEW_DEVICE_PAIRING":
        dev = ch["payload"]["requestingDevice"]
        acct["sessions"].append({"deviceId": dev, "trusted": True, "revoked": False, "createdAt": now()})
        preserve = list(dict.fromkeys((acct.get("preserve") or []) + [dev]))
        await db.rp_accounts.update_one({"agentId": agent_id, "domain": body.domain}, {"$set": {"sessions": acct["sessions"], "preserve": preserve}})
        extra["pairedDeviceId"] = dev
    await db.rp_challenges.update_one({"challengeId": body.challengeId}, {"$set": {"status": "APPROVED", "resolvedAt": now(), "uvSource": uv}})
    return await signed({"result": "APPROVED", "challengeId": body.challengeId, "userVerified": True, "uvSource": uv, **extra})


@api.put("/backup")
async def backup_put(request: Request):
    body, _, agent_id, sig, raw = await read_signed(request, BackupPut)
    agent = await load_agent(agent_id)
    verify_raw(agent["publicJwk"], sig, raw)
    if body.agentId != agent_id:
        raise RpErr(400, "AGENT_MISMATCH", "agentId mismatch")
    if hashlib.sha256(b64u_dec(body.ciphertext)).hexdigest() != body.ciphertextSha256:
        raise RpErr(400, "HASH_MISMATCH", "ciphertextSha256 mismatch")
    uv = None
    if body.mode == "TIER2_EXPORT":
        payload = {"action": "EXPORT_ENCRYPTED_BACKUP", "backupId": body.backupId, "ciphertextSha256": body.ciphertextSha256, "timestamp": body.timestamp}
        uv = verify_webauthn(agent, body.assertion, hashlib.sha256(canonical(payload)).digest())
        await db.rp_agents.update_one({"agentId": agent_id}, {"$set": {"backupSyncEnabled": True}})
    elif not agent.get("backupSyncEnabled"):
        raise RpErr(403, "SYNC_NOT_AUTHORIZED", "First backup export requires Tier 2 approval")
    prev = await db.rp_backups.find_one({"backupId": body.backupId}, {"_id": 0, "agentId": 1})
    if prev and prev["agentId"] != agent_id:
        raise RpErr(409, "BACKUP_OWNER_CONFLICT", "Backup slot owned by another agent")
    await db.rp_backups.replace_one({"backupId": body.backupId}, {
        "backupId": body.backupId, "agentId": agent_id, "iv": body.iv, "ciphertext": body.ciphertext,
        "ciphertextSha256": body.ciphertextSha256, "mode": body.mode, "updatedAt": now()}, upsert=True)
    return await signed({"result": "STORED", "backupId": body.backupId, "mode": body.mode, "uvSource": uv, "bytes": len(b64u_dec(body.ciphertext))})


@api.get("/backup/{backup_id}")
async def backup_get(backup_id: str):
    doc = await db.rp_backups.find_one({"backupId": backup_id}, {"_id": 0, "agentId": 0})
    if not doc:
        raise RpErr(404, "NO_BACKUP", "No backup found for this seed")
    return await signed(doc)


# ------------------------------------------------ mock RP-side views & simulators
@api.get("/rp/pending")
async def pending(agentId: str = Query(...)):
    items = await db.rp_challenges.find({"agentId": agentId, "status": "PENDING"}, {"_id": 0}).sort("createdAt", 1).to_list(50)
    return {"challenges": items}


@api.get("/rp/accounts/{agent_id}/{domain}")
async def account_view(agent_id: str, domain: str):
    acct = await db.rp_accounts.find_one({"agentId": agent_id, "domain": domain}, {"_id": 0})
    if not acct:
        raise RpErr(404, "UNKNOWN_ACCOUNT", "Not enrolled")
    return {
        "domain": domain, "activeFingerprint": fp(acct["activeVerifier"]), "stagedFingerprint": fp(acct["stagedVerifier"]),
        "previousSlotPresent": acct["previousVerifier"] is not None, "stagedRotationId": acct["stagedRotationId"],
        "lastCommittedRotationId": acct["lastCommittedRotationId"], "rotations": acct.get("rotations", 0),
        "sessions": acct["sessions"], "updatedAt": acct["updatedAt"],
    }


async def _trusted(agent_id: str, domain: str, device: str) -> bool:
    acct = await db.rp_accounts.find_one({"agentId": agent_id, "domain": domain}, {"_id": 0})
    if not acct:
        raise RpErr(404, "UNKNOWN_ACCOUNT", "Not enrolled")
    return any(s["deviceId"] == device and s["trusted"] and not s["revoked"] for s in acct["sessions"])


async def _create_step_up(agent_id, domain, action, context, device, ip) -> dict:
    cid = str(uuid.uuid4())
    payload = {"challengeId": cid, "domain": domain, "actionType": action, "humanReadableContext": context,
               "requestingDevice": device, "requestOriginIp": ip, "timestamp": now()}
    doc = {"challengeId": cid, "agentId": agent_id, "domain": domain, "kind": "STEP_UP", "status": "PENDING",
           "payload": payload, "payloadSha256": hashlib.sha256(canonical(payload)).hexdigest(),
           "requireUserVerification": True, "createdAt": now()}
    await db.rp_challenges.insert_one(dict(doc))
    return doc


@api.post("/rp/simulate/reset-request")
async def sim_reset(req: SimReset):
    if await _trusted(req.agentId, req.domain, req.deviceId):
        doc = await _create_step_up(req.agentId, req.domain, "APPROVE_PASSWORD_RESET",
                                    f"Password reset requested from trusted device '{req.deviceId}'", req.deviceId, req.originIp)
        return {"kind": "STEP_UP", "challengeId": doc["challengeId"], "isTrustedDevice": True}
    cid = str(uuid.uuid4())
    await db.rp_challenges.insert_one({"challengeId": cid, "agentId": req.agentId, "domain": req.domain, "kind": "RESET",
                                       "status": "PENDING", "requestOriginIp": req.originIp, "requestingDevice": req.deviceId,
                                       "isTrustedDevice": False, "createdAt": now()})
    return {"kind": "RESET", "challengeId": cid, "isTrustedDevice": False}


@api.post("/rp/simulate/step-up-request")
async def sim_step_up(req: SimStepUp):
    await _trusted(req.agentId, req.domain, req.requestingDevice)
    doc = await _create_step_up(req.agentId, req.domain, req.actionType, req.humanReadableContext, req.requestingDevice, req.requestOriginIp)
    return {"kind": "STEP_UP", "challengeId": doc["challengeId"], "payloadSha256": doc["payloadSha256"]}


@api.post("/rp/simulate/rogue-session")
async def sim_rogue(req: SimSession):
    res = await db.rp_accounts.update_one({"agentId": req.agentId, "domain": req.domain}, {"$push": {"sessions": {
        "deviceId": req.deviceId, "trusted": False, "revoked": False, "createdAt": now()}}})
    if res.matched_count == 0:
        raise RpErr(404, "UNKNOWN_ACCOUNT", "Not enrolled")
    return {"result": "SESSION_CREATED", "deviceId": req.deviceId}


class SvcLogin(BaseModel):
    username: str
    password: str
    deviceId: str = "web-browser"


class SvcChange(BaseModel):
    username: str
    currentPassword: str
    newPassword: str


class SvcOutage(BaseModel):
    on: bool


class NoticeAck(Strict):
    domain: str
    challengeId: str
    decision: Literal["ROTATED", "ROTATION_QUEUED_FOR_APPROVAL", "REMINDER_SENT", "IGNORED"]
    timestamp: int


class UvVerify(Strict):
    agentId: str
    actionType: str
    payloadSha256: str
    assertion: dict
    timestamp: int


class ReportSign(BaseModel):
    report: dict


class ReportVerify(BaseModel):
    report: dict
    rpSignature: str


def _pw_verifier_hex(password: str, domain: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), f"credential-agent:{domain}".encode(), 100000).hex()


async def _svc_up(domain: str):
    if await db.svc_status.find_one({"domain": domain, "outage": True}):
        raise RpErr(503, "SERVICE_OUTAGE", f"{domain} is offline")


# ------------------------------------------------ hosted demo services (real login, sessions, password change)
@api.get("/svc/{domain}/info")
async def svc_info(domain: str):
    st = await db.svc_status.find_one({"domain": domain}, {"_id": 0})
    n = await db.rp_accounts.count_documents({"domain": domain})
    return {"domain": domain, "outage": bool(st and st.get("outage")), "accounts": n}


@api.post("/svc/{domain}/admin/outage")
async def svc_outage(domain: str, req: SvcOutage):
    await db.svc_status.update_one({"domain": domain}, {"$set": {"outage": req.on, "at": now()}}, upsert=True)
    return {"domain": domain, "outage": req.on}


@api.post("/svc/{domain}/login")
async def svc_login(domain: str, req: SvcLogin, request: Request):
    await _svc_up(domain)
    acct = await db.rp_accounts.find_one({"domain": domain, "username": req.username}, {"_id": 0})
    v = acct and acct.get("activeVerifier")
    if not v or not hmac.compare_digest(v.split("$")[2], _pw_verifier_hex(req.password, domain)):
        raise RpErr(401, "INVALID_LOGIN", "Wrong username or password")
    token = uuid.uuid4().hex
    ip = (request.headers.get("x-forwarded-for") or (request.client.host if request.client else "")).split(",")[0].strip()
    sess = {"deviceId": req.deviceId, "trusted": req.deviceId in (acct.get("preserve") or []), "revoked": False,
            "createdAt": now(), "token": token, "ip": ip}
    await db.rp_accounts.update_one({"domain": domain, "username": req.username}, {"$push": {"sessions": sess}})
    return await signed({"result": "SIGNED_IN", "sessionToken": token, "username": req.username, "deviceId": req.deviceId})


@api.post("/svc/{domain}/logout")
async def svc_logout(domain: str, token: str = Query(...)):
    await db.rp_accounts.update_one({"domain": domain, "sessions.token": token}, {"$set": {"sessions.$.revoked": True, "sessions.$.revokedAt": now()}})
    return {"result": "SIGNED_OUT"}


@api.get("/svc/{domain}/me")
async def svc_me(domain: str, token: str = Query(...)):
    await _svc_up(domain)
    acct = await db.rp_accounts.find_one({"domain": domain, "sessions.token": token}, {"_id": 0})
    if not acct:
        raise RpErr(401, "NO_SESSION", "Session not found")
    mine = next(s for s in acct["sessions"] if s.get("token") == token)
    if mine["revoked"]:
        raise RpErr(401, "SESSION_REVOKED", "This session was signed out")
    return {"username": acct["username"], "domain": domain, "deviceId": mine["deviceId"], "passwordChangedAt": acct.get("passwordChangedAt"),
            "agentPasskeyRegistered": True, "agentKeyX": acct["publicJwk"]["x"][:16],
            "sessions": [{k: v for k, v in s.items() if k != "token"} for s in acct["sessions"]]}


@api.post("/svc/{domain}/change-password")
async def svc_change(domain: str, req: SvcChange):
    await _svc_up(domain)
    acct = await db.rp_accounts.find_one({"domain": domain, "username": req.username}, {"_id": 0})
    if not acct or not hmac.compare_digest(acct["activeVerifier"].split("$")[2], _pw_verifier_hex(req.currentPassword, domain)):
        raise RpErr(401, "INVALID_LOGIN", "Current password is wrong")
    if len(req.newPassword) < 12:
        raise RpErr(422, "WEAK_PASSWORD", "Use at least 12 characters")
    await db.rp_accounts.update_one({"domain": domain, "username": req.username}, {"$set": {
        "activeVerifier": f"pbkdf2-sha256$100000${_pw_verifier_hex(req.newPassword, domain)}", "passwordChangedAt": now(),
        "lastManualChangeAt": now(), "previousVerifier": None, "stagedVerifier": None, "stagedRotationId": None}})
    return {"result": "PASSWORD_CHANGED_BY_USER"}


@api.get("/svc/{domain}/status")
async def svc_status_view(domain: str, username: str = Query(...)):
    acct = await db.rp_accounts.find_one({"domain": domain, "username": username}, {"_id": 0})
    if not acct:
        raise RpErr(404, "UNKNOWN_ACCOUNT", "Not enrolled")
    st = await db.svc_status.find_one({"domain": domain}, {"_id": 0})
    return {"passwordChangedAt": acct.get("passwordChangedAt"), "lastManualChangeAt": acct.get("lastManualChangeAt"),
            "outage": bool(st and st.get("outage"))}


@api.post("/rp/simulate/suspicious-login")
async def sim_suspicious(req: SimReset):
    cid = str(uuid.uuid4())
    await db.rp_challenges.insert_one({"challengeId": cid, "agentId": req.agentId, "domain": req.domain, "kind": "NOTICE",
                                       "reason": "SUSPICIOUS_LOGIN", "status": "PENDING", "requestOriginIp": req.originIp,
                                       "requestingDevice": req.deviceId, "createdAt": now()})
    return {"kind": "NOTICE", "challengeId": cid}


@api.post(WK + "/notice-ack")
async def notice_ack(request: Request):
    body, _, agent_id, sig, raw = await read_signed(request, NoticeAck)
    await load_account(agent_id, body.domain, sig, raw)
    res = await db.rp_challenges.update_one({"challengeId": body.challengeId, "agentId": agent_id, "kind": "NOTICE", "status": "PENDING"},
                                            {"$set": {"status": body.decision, "resolvedAt": now()}})
    if res.matched_count == 0:
        raise RpErr(409, "ALREADY_RESOLVED", "Notice not pending")
    return await signed({"result": "ACKNOWLEDGED", "decision": body.decision})


@api.post(WK + "/uv-verify")
async def uv_verify(request: Request):
    body, _, agent_id, sig, raw = await read_signed(request, UvVerify)
    agent = await load_agent(agent_id)
    verify_raw(agent["publicJwk"], sig, raw)
    uv = verify_webauthn(agent, body.assertion, bytes.fromhex(body.payloadSha256))
    return await signed({"verified": True, "uvSource": uv, "actionType": body.actionType, "payloadSha256": body.payloadSha256})


# ------------------------------------------------ signed test report
@api.post("/report/sign")
async def report_sign(req: ReportSign):
    der = (await rp_key()).sign(canonical(req.report), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return {"rpSignature": b64u_enc(r.to_bytes(32, "big") + s.to_bytes(32, "big")), "signedAt": now()}


@api.post("/report/verify")
async def report_verify(req: ReportVerify):
    try:
        sig = b64u_dec(req.rpSignature)
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        (await rp_key()).public_key().verify(der, canonical(req.report), ec.ECDSA(hashes.SHA256()))
        return {"valid": True}
    except (InvalidSignature, ValueError):
        return {"valid": False}


# ------------------------------------------------ patent documents
@api.get("/docs")
async def docs_list():
    return {"docs": [{"id": k, "title": v[0]} for k, v in DOCS.items()]}


@api.get("/docs/{doc_id}.pdf")
async def doc_pdf(doc_id: str):
    if doc_id not in DOCS:
        raise RpErr(404, "NO_DOC", "Unknown document")
    title, md = DOCS[doc_id]
    pdf = await asyncio.to_thread(render_pdf, title, md)
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="Passtate-{doc_id}.pdf"'})


@api.get("/docs/{doc_id}")
async def doc_get(doc_id: str):
    if doc_id not in DOCS:
        raise RpErr(404, "NO_DOC", "Unknown document")
    return {"id": doc_id, "title": DOCS[doc_id][0], "markdown": DOCS[doc_id][1]}


app.include_router(api)
app.include_router(make_aws_router(db, read_signed, signed, RpErr, load_agent, verify_raw, Strict))
app.add_middleware(CORSMiddleware, allow_credentials=True, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
                   expose_headers=["X-RP-Signature"])


@app.on_event("startup")
async def start_index_build():
    app.state.index_task = asyncio.create_task(ensure_indexes())
    app.state.dep_task = asyncio.create_task(dependent_loop(db))


@app.on_event("shutdown")
async def shutdown_db_client():
    app.state.index_task.cancel()
    app.state.dep_task.cancel()
    with suppress(asyncio.CancelledError):
        await app.state.index_task
    client.close()
