"""AWS IAM access-key connector + a live 'dependent app' that keeps calling AWS with whatever key it was given.

Secrets are carried only in signed request bodies / the dependent-app record and are never logged or audited.
"""
import asyncio
import logging
import os
import time
from typing import Optional

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, Request

logger = logging.getLogger("aws-connector")
REGION = os.environ.get("AWS_REGION", "us-east-1")
CFG = Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 2})


def _env_pair():
    k, s = os.environ.get("AWS_BOOTSTRAP_ACCESS_KEY_ID"), os.environ.get("AWS_BOOTSTRAP_SECRET_ACCESS_KEY")
    return (k, s) if k and s and not k.startswith("placeholder") else (None, None)


def _client(service: str, kid: str, secret: str):
    return boto3.client(service, region_name=REGION, aws_access_key_id=kid, aws_secret_access_key=secret, config=CFG)


def _whoami(kid: str, secret: str) -> dict:
    ident = _client("sts", kid, secret).get_caller_identity()
    return {"arn": ident["Arn"], "account": ident["Account"], "userId": ident["UserId"]}


def mask(kid: Optional[str]) -> Optional[str]:
    return f"{kid[:4]}…{kid[-4:]}" if kid else None


def make_router(db, read_signed, signed, RpErr, load_agent, verify_raw, Strict):
    router = APIRouter(prefix="/api")

    class Creds(Strict):
        agentId: str
        accessKeyId: str
        secretAccessKey: str
        timestamp: int

    class DeleteKey(Strict):
        agentId: str
        accessKeyId: str
        secretAccessKey: str
        deleteAccessKeyId: str
        timestamp: int

    class Claim(Strict):
        agentId: str
        timestamp: int

    async def authed(request: Request, model):
        body, _, agent_id, sig, raw = await read_signed(request, model)
        agent = await load_agent(agent_id)
        verify_raw(agent["publicJwk"], sig, raw)
        if body.agentId != agent_id:
            raise RpErr(400, "AGENT_MISMATCH", "agentId mismatch")
        return body

    async def aws(fn, *args):
        try:
            return await asyncio.to_thread(fn, *args)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "ClientError")
            raise RpErr(502, f"AWS_{code}", "AWS rejected the request")
        except BotoCoreError as exc:
            raise RpErr(503, "AWS_UNREACHABLE", exc.__class__.__name__)

    @router.get("/connectors/aws/status")
    async def status():
        k, _ = _env_pair()
        claim = await db.aws_claim.find_one({"name": "bootstrap"}, {"_id": 0})
        return {"configured": bool(k), "region": REGION, "bootstrapClaimedBy": claim["agentId"][:8] if claim else None}

    @router.post("/connectors/aws/bootstrap")
    async def bootstrap(request: Request):
        body = await authed(request, Claim)
        k, s = _env_pair()
        if not k:
            raise RpErr(412, "AWS_NOT_CONFIGURED", "Add the AWS test user's access key first")
        claim = await db.aws_claim.find_one({"name": "bootstrap"}, {"_id": 0})
        if claim and claim["agentId"] != body.agentId:
            raise RpErr(409, "BOOTSTRAP_CLAIMED", "The AWS demo key belongs to the presenter agent")
        ident = await aws(_whoami, k, s)
        await db.aws_claim.update_one({"name": "bootstrap"}, {"$set": {"agentId": body.agentId, "at": int(time.time())}}, upsert=True)
        return await signed({"accessKeyId": k, "secretAccessKey": s, **ident})

    @router.post("/connectors/aws/whoami")
    async def whoami(request: Request):
        b = await authed(request, Creds)
        return await signed(await aws(_whoami, b.accessKeyId, b.secretAccessKey))

    @router.post("/connectors/aws/list-keys")
    async def list_keys(request: Request):
        b = await authed(request, Creds)
        meta = await aws(lambda: _client("iam", b.accessKeyId, b.secretAccessKey).list_access_keys()["AccessKeyMetadata"])
        return await signed({"keys": [{"accessKeyId": m["AccessKeyId"], "status": m["Status"], "created": int(m["CreateDate"].timestamp())} for m in meta]})

    @router.post("/connectors/aws/create-key")
    async def create_key(request: Request):
        b = await authed(request, Creds)
        iam = _client("iam", b.accessKeyId, b.secretAccessKey)
        meta = await aws(lambda: iam.list_access_keys()["AccessKeyMetadata"])
        if len(meta) >= 2:
            raise RpErr(409, "AWS_TWO_KEYS", "User already has 2 keys - recovery must delete the dead one first")
        new = await aws(lambda: iam.create_access_key()["AccessKey"])
        return await signed({"accessKeyId": new["AccessKeyId"], "secretAccessKey": new["SecretAccessKey"]})

    @router.post("/connectors/aws/verify")
    async def verify(request: Request):
        b = await authed(request, Creds)
        last = None
        for delay in (0, 1, 2, 3, 4, 5):
            await asyncio.sleep(delay)
            try:
                ident = await asyncio.to_thread(_whoami, b.accessKeyId, b.secretAccessKey)
                return await signed({"verified": True, **ident})
            except (ClientError, BotoCoreError) as exc:
                last = exc.__class__.__name__
        raise RpErr(409, "AWS_KEY_NOT_USABLE", f"New key did not verify ({last})")

    @router.post("/connectors/aws/delete-key")
    async def delete_key(request: Request):
        b = await authed(request, DeleteKey)
        dep = await db.dependent_app.find_one({"name": "aws"}, {"_id": 0})
        if dep and dep.get("accessKeyId") == b.deleteAccessKeyId:
            raise RpErr(409, "KEY_IN_USE", "Dependent app still uses this key - propagate first")
        await aws(lambda: _client("iam", b.accessKeyId, b.secretAccessKey).delete_access_key(AccessKeyId=b.deleteAccessKeyId))
        return await signed({"deleted": b.deleteAccessKeyId})

    # ---------------------------------------------------------- dependent app
    @router.post("/dependent/aws/propagate")
    async def propagate(request: Request):
        b = await authed(request, Creds)
        ident = await aws(_whoami, b.accessKeyId, b.secretAccessKey)
        await db.dependent_app.update_one({"name": "aws"}, {"$set": {
            "accessKeyId": b.accessKeyId, "secretAccessKey": b.secretAccessKey, "since": int(time.time()), "owner": b.agentId}}, upsert=True)
        return await signed({"propagated": True, "arn": ident["arn"], "accessKeyId": mask(b.accessKeyId)})

    @router.get("/dependent/aws/status")
    async def dep_status():
        d = await db.dependent_app.find_one({"name": "aws"}, {"_id": 0, "secretAccessKey": 0})
        if not d:
            return {"configured": False, "history": []}
        hist = d.get("history", [])
        ok = sum(1 for h in hist if h["ok"])
        return {
            "configured": True, "accessKeyId": mask(d.get("accessKeyId")), "rawKeyId": d.get("accessKeyId"), "since": d.get("since"),
            "lastCheck": hist[-1] if hist else None, "history": hist[-40:], "uptimePct": round(100 * ok / len(hist), 1) if hist else None,
            "totalCalls": d.get("totalCalls", 0), "failedCalls": d.get("failedCalls", 0),
        }

    return router


async def dependent_loop(db):
    """The 'dependent app': calls AWS every 5 s with its current key and records whether it still works."""
    while True:
        try:
            d = await db.dependent_app.find_one({"name": "aws"}, {"_id": 0})
            if d and d.get("accessKeyId"):
                entry = {"ts": int(time.time()), "keyId": mask(d["accessKeyId"]), "rawKeyId": d["accessKeyId"]}
                try:
                    await asyncio.to_thread(_whoami, d["accessKeyId"], d["secretAccessKey"])
                    entry["ok"] = True
                except (ClientError, BotoCoreError) as exc:
                    entry.update(ok=False, error=exc.__class__.__name__)
                await db.dependent_app.update_one({"name": "aws"}, {
                    "$push": {"history": {"$each": [entry], "$slice": -120}},
                    "$inc": {"totalCalls": 1, "failedCalls": 0 if entry["ok"] else 1}})
        except Exception as exc:  # keep the loop alive
            logger.error("dependent loop: %s", exc.__class__.__name__)
        await asyncio.sleep(5)
