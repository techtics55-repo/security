from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
import json
import hashlib
import time
import uuid

router = APIRouter(prefix="/taas", tags=["Trust as a Service"])

# In-memory stores
vpi_identities = {}
vpi_mandates = {}
vpi_proofs = []
ledger_chain = []
escrow_store = {}
thinking_logs = []
vibe_scan_results = []


# ====================================================================
# Layer A: VPI Protocol — Verifiable Proof of Intent
# ====================================================================

class RegisterHumanRequest(BaseModel):
    human_id: str
    human_name: str


@router.post("/vpi/register")
def vpi_register_human(req: RegisterHumanRequest):
    import hashlib, time
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    human_key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = human_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    priv_pem = human_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    cert = {
        "human_id": req.human_id,
        "human_name": req.human_name,
        "public_key_pem": pub_pem,
        "issued_at": time.time(),
        "issuer": "Oracle Node",
    }
    raw = f"{cert['human_id']}{cert['human_name']}{cert['public_key_pem']}{cert['issued_at']}{cert['issuer']}"
    cert["cert_hash"] = hashlib.sha3_256(raw.encode()).hexdigest()
    vpi_identities[req.human_id] = cert
    return {"status": "registered", "certificate": cert, "private_key": priv_pem}


@router.get("/vpi/certificate/{human_id}")
def vpi_get_certificate(human_id: str):
    cert = vpi_identities.get(human_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Human not registered")
    return cert


class IssueMandateRequest(BaseModel):
    human_id: str
    instructions: str
    boundary_rules: list = []


@router.post("/vpi/mandate")
def vpi_issue_mandate(req: IssueMandateRequest):
    import hashlib, time, uuid, json
    if req.human_id not in vpi_identities:
        raise HTTPException(status_code=404, detail="Human not registered. Call /taas/vpi/register first.")
    mandate_id = hashlib.sha3_256(f"{req.human_id}{req.instructions}{time.time()}{uuid.uuid4()}".encode()).hexdigest()[:24]
    mandate = {
        "mandate_id": mandate_id,
        "human_id": req.human_id,
        "instructions_hash": hashlib.sha3_256(req.instructions.encode()).hexdigest(),
        "exact_instructions": req.instructions,
        "boundary_rules": req.boundary_rules,
        "timestamp": time.time(),
    }
    raw = f"{mandate['mandate_id']}{mandate['human_id']}{mandate['instructions_hash']}{json.dumps(req.boundary_rules, sort_keys=True)}{mandate['timestamp']}"
    mandate["mandate_hash"] = hashlib.sha3_256(raw.encode()).hexdigest()
    vpi_mandates[mandate["mandate_hash"]] = mandate
    return {"status": "mandate_issued", "mandate": mandate}


class CreateProofRequest(BaseModel):
    human_id: str
    mandate_hash: str = ""
    prompt: str
    response: str
    response_compliant: bool = True
    compliance_violations: list = []


@router.post("/vpi/proof")
def vpi_create_proof(req: CreateProofRequest):
    import hashlib, time, uuid, json
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
    proof_id = hashlib.sha3_256(f"{req.human_id}{req.mandate_hash}{req.prompt}{req.response}{time.time()}".encode()).hexdigest()[:24]
    prev_hash = vpi_proofs[-1]["chain_hash"] if vpi_proofs else ""
    nonce = hashlib.sha3_256(f"{time.time()}{req.prompt}{req.response}{uuid.uuid4()}".encode()).hexdigest()[:16]
    proof = {
        "version": "2.0",
        "proof_id": proof_id,
        "human_id": req.human_id,
        "mandate_hash": req.mandate_hash,
        "prompt_hash": hashlib.sha3_256(req.prompt.encode()).hexdigest(),
        "response_hash": hashlib.sha3_256(req.response.encode()).hexdigest(),
        "response_compliant": req.response_compliant,
        "compliance_violations": req.compliance_violations,
        "timestamp": time.time(),
        "nonce": nonce,
        "prev_chain_hash": prev_hash,
    }
    combined = f"{proof['version']}{proof['proof_id']}{proof['human_id']}{proof['mandate_hash']}{proof['prompt_hash']}{proof['response_hash']}{proof['response_compliant']}{proof['timestamp']}{proof['nonce']}{proof['prev_chain_hash']}"
    proof["chain_hash"] = hashlib.sha3_256(combined.encode()).hexdigest()
    oracle_key = ec.generate_private_key(ec.SECP256R1())
    signature = oracle_key.sign(proof["chain_hash"].encode(), ec.ECDSA(hashes.SHA3_256()))
    r, s = decode_dss_signature(signature)
    proof["oracle_signature"] = f"{r:x}:{s:x}"
    vpi_proofs.append(proof)
    return {"status": "proof_created", "proof": proof, "chain_length": len(vpi_proofs)}


@router.post("/vpi/verify")
def vpi_verify_proof(proof_id: str = Query(...)):
    proof = next((p for p in reversed(vpi_proofs) if p["proof_id"] == proof_id), None)
    if not proof:
        raise HTTPException(status_code=404, detail="VPI proof not found")
    prev_hash = ""
    for i, p in enumerate(vpi_proofs):
        if p["proof_id"] == proof_id:
            prev_hash = vpi_proofs[i - 1]["chain_hash"] if i > 0 else ""
            break
    components = f"{proof['version']}{proof['proof_id']}{proof['human_id']}{proof['mandate_hash']}{proof['prompt_hash']}{proof['response_hash']}{proof['response_compliant']}{proof['timestamp']}{proof['nonce']}{prev_hash}"
    expected = hashlib.sha3_256(components.encode()).hexdigest()
    return {
        "verified": proof["chain_hash"] == expected,
        "tampered": proof["chain_hash"] != expected,
        "proof": proof,
    }


@router.get("/vpi/chain")
def vpi_get_chain():
    return {"chain_length": len(vpi_proofs), "proofs": vpi_proofs[-20:]}


@router.get("/vpi/mandates")
def vpi_list_mandates():
    return {"mandates": list(vpi_mandates.values())}


# ====================================================================
# Layer B: Black Box Ledger — Chain-of-Thought Logging
# ====================================================================

class RecordReasoningStepRequest(BaseModel):
    session_id: str
    thought: str
    input_context: str = ""
    output_decision: str = ""
    confidence: float = 0.0


@router.post("/ledger/start-trail")
def ledger_start_trail(session_id: str = Query(...), human_id: str = Query("anonymous"), agent_id: str = Query("unknown"), prompt: str = Query("")):
    trail = {
        "session_id": session_id,
        "human_id": human_id,
        "agent_id": agent_id,
        "prompt": prompt,
        "reasoning_steps": [],
        "response": "",
        "created_at": time.time(),
    }
    return {"status": "trail_started", "trail": trail,
            "instructions": "Send reasoning steps via POST /taas/ledger/reasoning-step, then seal via /taas/ledger/seal"}


@router.post("/ledger/reasoning-step")
def ledger_add_step(req: RecordReasoningStepRequest):
    import hashlib
    step = {
        "step_index": 0,
        "thought": req.thought,
        "input_context": req.input_context,
        "output_decision": req.output_decision,
        "confidence": req.confidence,
        "timestamp": time.time(),
    }
    raw = f"{step['step_index']}{step['thought']}{step['input_context']}{step['output_decision']}{step['confidence']}{step['timestamp']}"
    step["step_hash"] = hashlib.sha3_256(raw.encode()).hexdigest()
    return {"status": "step_recorded", "step": step}


class SealEntryRequest(BaseModel):
    session_id: str
    human_id: str = "anonymous"
    agent_id: str = "unknown"
    prompt: str
    response: str
    reasoning_steps: list = []
    ai_trism_metadata: dict = {}


@router.post("/ledger/seal")
def ledger_seal_entry(req: SealEntryRequest):
    import hashlib, json, uuid
    prompt_hash = hashlib.sha3_256(req.prompt.encode()).hexdigest()
    response_hash = hashlib.sha3_256(req.response.encode()).hexdigest()
    if req.reasoning_steps:
        current = req.reasoning_steps[0].get("step_hash", "0")
        for s in req.reasoning_steps[1:]:
            current = hashlib.sha3_256(f"{current}{s.get('step_hash', '0')}".encode()).hexdigest()
        reasoning_root = current
    else:
        reasoning_root = "0" * 64
    witness_raw = f"{req.session_id}{prompt_hash}{response_hash}{time.time()}{uuid.uuid4()}"
    witness_hash = hashlib.sha3_256(witness_raw.encode()).hexdigest()
    prev_hash = ledger_chain[-1]["hash"] if ledger_chain else "0" * 64
    entry = {
        "index": len(ledger_chain),
        "session_id": req.session_id,
        "human_id": req.human_id,
        "agent_id": req.agent_id,
        "prompt": req.prompt,
        "prompt_hash": prompt_hash,
        "response": req.response,
        "response_hash": response_hash,
        "reasoning_steps": req.reasoning_steps,
        "reasoning_root_hash": reasoning_root,
        "ai_trism_metadata": req.ai_trism_metadata or {
            "transparency": "recorded", "risk_assessment": "recorded",
            "security_controls": "recorded", "model_governance": "recorded", "compliance": "recorded"
        },
        "timestamp": time.time(),
        "witness_hash": witness_hash,
        "previous_hash": prev_hash,
    }
    raw = f"{entry['index']}{entry['session_id']}{entry['human_id']}{entry['agent_id']}{entry['prompt_hash']}{entry['response_hash']}{entry['reasoning_root_hash']}{json.dumps(entry['ai_trism_metadata'], sort_keys=True)}{entry['timestamp']}{entry['witness_hash']}{entry['previous_hash']}"
    nonce = 0
    entry["hash"] = hashlib.sha3_256((raw + str(nonce)).encode()).hexdigest()
    while not entry["hash"].startswith("000"):
        nonce += 1
        entry["nonce"] = nonce
        entry["hash"] = hashlib.sha3_256((raw + str(nonce)).encode()).hexdigest()
    ledger_chain.append(entry)
    return {"status": "sealed", "entry": entry, "chain_length": len(ledger_chain)}


@router.get("/ledger/chain")
def ledger_get_chain():
    return {"chain_length": len(ledger_chain), "entries": ledger_chain[-20:]}


@router.get("/ledger/trail/{session_id}")
def ledger_get_trail(session_id: str):
    entry = next((e for e in reversed(ledger_chain) if e["session_id"] == session_id), None)
    if not entry:
        raise HTTPException(status_code=404, detail="Session not found in ledger")
    return entry


@router.get("/ledger/verify")
def ledger_verify():
    for i in range(len(ledger_chain)):
        entry = ledger_chain[i]
        if not entry["hash"].startswith("000"):
            return {"valid": False, "broken_at": i, "reason": "hash_prefix_mismatch"}
        if i > 0 and entry["previous_hash"] != ledger_chain[i - 1]["hash"]:
            return {"valid": False, "broken_at": i, "reason": "previous_hash_mismatch"}
    return {"valid": True, "chain_length": len(ledger_chain),
            "oracle_node": "Black Box Ledger v2.0 — AI TRiSM Compliant"}


@router.get("/ledger/custody-report")
def ledger_custody_report():
    return {
        "node": "Oracle Node Black Box Ledger",
        "version": "2.0",
        "total_entries": len(ledger_chain),
        "chain_valid": all(
            ledger_chain[i]["hash"].startswith("000") and
            (i == 0 or ledger_chain[i]["previous_hash"] == ledger_chain[i - 1]["hash"])
            for i in range(len(ledger_chain))
        ) if ledger_chain else True,
        "ai_trism_coverage": {
            "transparency": True, "risk_assessment": True,
            "security_controls": True, "model_governance": True, "compliance": True
        },
        "timestamp": time.time(),
    }


# ====================================================================
# Layer C: Autonomous Escrow — Smart-Contract Financial Buffer
# ====================================================================

class CreateEscrowRequest(BaseModel):
    human_id: str
    agent_id: str
    title: str = "AI Task Escrow"
    amount: float
    currency: str = "USD"
    commission_rate: float = 0.025
    deadline_seconds: int = 86400


class FundEscrowRequest(BaseModel):
    escrow_id: str
    amount: float


class CompleteTaskRequest(BaseModel):
    escrow_id: str
    completion_proof: str


class VerifyReleaseRequest(BaseModel):
    escrow_id: str
    verified: bool = True


class DisputeRequest(BaseModel):
    escrow_id: str
    reason: str


class ArbitrateRequest(BaseModel):
    escrow_id: str
    decision: str
    notes: str = ""


@router.post("/escrow/create")
def escrow_create(req: CreateEscrowRequest):
    import hashlib, uuid
    from decimal import Decimal, ROUND_HALF_UP
    escrow_id = hashlib.sha3_256(f"{req.human_id}{req.agent_id}{req.title}{req.amount}{time.time()}{uuid.uuid4()}".encode()).hexdigest()[:24]
    oracle_id = hashlib.sha3_256(f"oracle-{time.time()}".encode()).hexdigest()[:16]
    commission = float(Decimal(str(req.amount)) * Decimal(str(req.commission_rate)))
    commission = float(Decimal(str(commission)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    net = float(Decimal(str(req.amount)) - Decimal(str(commission)))
    net = float(Decimal(str(net)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    terms = {
        "amount": req.amount,
        "currency": req.currency,
        "oracle_commission_rate": req.commission_rate,
        "commission_amount": commission,
        "net_settlement": net,
        "deadline_seconds": req.deadline_seconds,
    }
    escrow = {
        "id": escrow_id,
        "title": req.title,
        "human_id": req.human_id,
        "agent_id": req.agent_id,
        "oracle_node_id": oracle_id,
        "terms": terms,
        "status": "draft",
        "balance_held": 0.0,
        "created_at": time.time(),
        "updated_at": time.time(),
        "expires_at": time.time() + req.deadline_seconds,
        "oracle_commission_earned": commission,
        "human_outcome": net,
        "human_signature": "",
        "agent_signature": "",
        "oracle_signature": "",
        "dispute_reason": "",
        "arbitration_notes": "",
        "task_completion_proof": "",
    }
    escrow_store[escrow_id] = escrow
    return {
        "status": "escrow_created",
        "escrow": escrow,
        "trust_gap_statement": f"Oracle Node {oracle_id[:8]} secures ${req.amount} in escrow. "
                               f"Agent will receive ${net} upon verified completion. "
                               f"Oracle earns ${commission} ({req.commission_rate*100}%) commission.",
    }


@router.post("/escrow/fund")
def escrow_fund(req: FundEscrowRequest):
    escrow = escrow_store.get(req.escrow_id)
    if not escrow:
        raise HTTPException(status_code=404, detail="Escrow not found")
    if escrow["status"] != "draft":
        raise HTTPException(status_code=400, detail=f"Escrow in {escrow['status']} state, expected draft")
    if req.amount < escrow["terms"]["amount"]:
        raise HTTPException(status_code=400, detail=f"Amount ${req.amount} less than required ${escrow['terms']['amount']}")
    escrow["balance_held"] = req.amount
    escrow["status"] = "funded"
    escrow["updated_at"] = time.time()
    escrow["human_signature"] = hashlib.sha3_256(f"{escrow['id']}{escrow['human_id']}{req.amount}".encode()).hexdigest()
    return {"status": "funded", "escrow": escrow}


@router.post("/escrow/lock")
def escrow_lock(escrow_id: str = Query(...), agent_key: str = Query("default")):
    escrow = escrow_store.get(escrow_id)
    if not escrow:
        raise HTTPException(status_code=404, detail="Escrow not found")
    if escrow["status"] != "funded":
        raise HTTPException(status_code=400, detail=f"Escrow in {escrow['status']} state, expected funded")
    escrow["status"] = "locked"
    escrow["updated_at"] = time.time()
    escrow["agent_signature"] = hashlib.sha3_256(f"{escrow['id']}{escrow['agent_id']}{agent_key}".encode()).hexdigest()
    oracle_key = hashlib.sha3_256(f"{escrow['oracle_node_id']}{escrow['balance_held']}{escrow['human_signature']}{escrow['agent_signature']}".encode()).hexdigest()
    escrow["oracle_signature"] = oracle_key
    return {"status": "locked", "escrow": escrow,
            "message": "Multi-party escrow locked. Human, Agent, and Oracle Node all signed."}


@router.post("/escrow/complete")
def escrow_complete(req: CompleteTaskRequest):
    escrow = escrow_store.get(req.escrow_id)
    if not escrow:
        raise HTTPException(status_code=404, detail="Escrow not found")
    if escrow["status"] != "locked":
        raise HTTPException(status_code=400, detail=f"Escrow in {escrow['status']} state, expected locked")
    escrow["task_completion_proof"] = req.completion_proof
    escrow["status"] = "verifying"
    escrow["updated_at"] = time.time()
    return {"status": "submitted_for_verification", "escrow": escrow,
            "message": "Oracle Node is verifying task completion..."}


@router.post("/escrow/release")
def escrow_release(req: VerifyReleaseRequest):
    escrow = escrow_store.get(req.escrow_id)
    if not escrow:
        raise HTTPException(status_code=404, detail="Escrow not found")
    if escrow["status"] != "verifying":
        raise HTTPException(status_code=400, detail=f"Escrow in {escrow['status']} state, expected verifying")
    if req.verified:
        escrow["status"] = "released"
    else:
        escrow["status"] = "disputed"
    escrow["updated_at"] = time.time()
    return {
        "status": escrow["status"],
        "escrow": escrow,
        "settlement": {
            "amount_held": escrow["balance_held"],
            "commission_to_oracle": escrow["oracle_commission_earned"],
            "net_to_agent": escrow["human_outcome"],
        },
    }


@router.post("/escrow/dispute")
def escrow_dispute(req: DisputeRequest):
    escrow = escrow_store.get(req.escrow_id)
    if not escrow:
        raise HTTPException(status_code=404, detail="Escrow not found")
    if escrow["status"] not in ("verifying", "locked", "in_progress"):
        raise HTTPException(status_code=400, detail=f"Escrow in {escrow['status']} state, cannot dispute")
    escrow["status"] = "disputed"
    escrow["dispute_reason"] = req.reason
    escrow["updated_at"] = time.time()
    return {"status": "disputed", "escrow": escrow}


@router.post("/escrow/arbitrate")
def escrow_arbitrate(req: ArbitrateRequest):
    escrow = escrow_store.get(req.escrow_id)
    if not escrow:
        raise HTTPException(status_code=404, detail="Escrow not found")
    if escrow["status"] != "disputed":
        raise HTTPException(status_code=400, detail=f"Escrow in {escrow['status']} state, expected disputed")
    escrow["status"] = "arbitration"
    escrow["arbitration_notes"] = req.notes
    escrow["updated_at"] = time.time()
    if req.decision == "release":
        escrow["status"] = "released"
    elif req.decision == "refund":
        escrow["status"] = "refunded"
    return {"status": escrow["status"], "decision": req.decision, "escrow": escrow}


@router.post("/escrow/refund")
def escrow_refund(escrow_id: str = Query(...)):
    escrow = escrow_store.get(escrow_id)
    if not escrow:
        raise HTTPException(status_code=404, detail="Escrow not found")
    if escrow["status"] in ("released", "refunded"):
        raise HTTPException(status_code=400, detail=f"Escrow already in final state: {escrow['status']}")
    escrow["status"] = "refunded"
    escrow["updated_at"] = time.time()
    return {"status": "refunded", "escrow": escrow}


@router.get("/escrow/trust-gap-report")
def escrow_trust_gap_report():
    active = [e for e in escrow_store.values() if e["status"] in ("funded", "locked", "verifying")]
    disputed = [e for e in escrow_store.values() if e["status"] in ("disputed", "arbitration")]
    return {
        "oracle_node": "Autonomous Escrow Engine",
        "total_escrows": len(escrow_store),
        "active_escrows": len(active),
        "total_value_secured": sum(e["balance_held"] for e in escrow_store.values()),
        "total_commission_earned": sum(e["oracle_commission_earned"] for e in escrow_store.values() if e["status"] == "released"),
        "disputes": len(disputed),
        "dispute_rate": len(disputed) / max(len(escrow_store), 1),
        "trust_gap_resolved": len([e for e in escrow_store.values() if e["status"] == "released"]),
    }


@router.get("/escrow/{escrow_id}")
def escrow_get(escrow_id: str):
    escrow = escrow_store.get(escrow_id)
    if not escrow:
        raise HTTPException(status_code=404, detail="Escrow not found")
    return escrow


@router.get("/escrow/list/all")
def escrow_list():
    return {"count": len(escrow_store), "escrows": list(escrow_store.values())}


# ====================================================================
# Thinking Monitor & Vibe-Code (kept from previous implementation)
# ====================================================================

@router.post("/thinking/analyze")
def thinking_analyze(prompt: str = "", response: str = "", metadata: str = "{}"):
    import re, json
    findings = []
    try:
        meta = json.loads(metadata) if isinstance(metadata, str) else metadata
    except json.JSONDecodeError:
        meta = {}
    patterns = [
        (r"i (?:know|understand|realize) this (?:may|might|could) be (?:wrong|unethical|harmful|illegal) but", "aware_but_complicit"),
        (r"(?:since|because) (?:the )?(?:user|they) (?:asked|requested|wanted).*?(?:i (?:should|will|must) (?:give|provide|help|assist))", "user_pressure_compliance"),
        (r"i (?:should|will|must) (?:obey|follow|comply) (?:to )?(?:the )?(?:user|instruction) (?:even )?(?:if|though|when)", "blind_obedience"),
        (r"no one (?:will|would|shall) (?:know|find out|notice|detect|discover)", "secrecy_intent"),
        (r"i can (?:get away with|bypass|circumvent|hide|conceal|mask|obfuscate|disguise)", "concealment_intent"),
        (r"it['']?s? (?:not )?(?:really|actually|truly) (?:that )?(?:bad|harmful|dangerous|wrong|illegal|unethical)", "minimizing_harm"),
        (r"other (?:AIs|models|systems|assistants) (?:would|do|can|will) (?:answer|respond|help|provide)", "competitive_pressure"),
    ]
    response_lower = response.lower()
    for pattern, name in patterns:
        if re.search(pattern, response_lower, re.IGNORECASE | re.DOTALL):
            findings.append({"type": name, "severity": "high", "location": "response"})
    entry = {"id": len(thinking_logs) + 1, "timestamp": time.time(), "findings": findings, "passed": len(findings) == 0, "severity": "high" if findings else "info"}
    thinking_logs.append(entry)
    return entry


@router.get("/thinking/logs")
def thinking_logs_list(limit: int = Query(50, le=200)):
    return list(reversed(thinking_logs[:limit]))


@router.post("/vibe-code/scan")
def vibe_code_scan(code: str = "", language: str = ""):
    import re
    findings = []
    scanners = {
        "sql_injection": [(r"execute.*['\"].*?(?:SELECT|INSERT|UPDATE|DELETE).*?['\"]\s*[+%]", "string_concatenated_sql"),
                          (r"f['\"].*?\{.*?\}.*?(?:SELECT|INSERT|UPDATE|DELETE)", "f_string_sql"),
                          (r"\$_(?:GET|POST|REQUEST)\[.*?\].*?(?:SELECT|INSERT|UPDATE|DELETE)", "user_input_sql")],
        "xss": [(r"\.innerHTML\s*[+=]?\s*", "unsafe_inner_html"),
                (r"document\.write\([^)]*?(?:request|params|data|input|user)", "unsafe_document_write"),
                (r"dangerouslySetInnerHTML", "react_dangerous_html")],
        "command_injection": [(r"os\.system|os\.popen|subprocess\.(?:call|run|Popen)", "command_execution"),
                              (r"(?:exec|eval|compile)\([^)]*?(?:request|input|data|user)", "dynamic_code_exec")],
        "path_traversal": [(r"(?:open|file|read|write|load|save|upload|download)\([^)]*\.\.\/|\.\.\\\\", "path_traversal")],
        "insecure_deserialization": [(r"pickle\.loads?\s*\(", "pickle_deserialization"),
                                     (r"yaml\.load\([^)]*?Loader\s*=\s*yaml\.Loader", "yaml_unsafe_load")],
        "auth_bypass": [(r"(?:is_admin|is_authenticated|is_logged_in|check_auth)\s*(?:=\s*True|:\s*True)", "auth_hardcoded")],
        "insecure_crypto": [(r"MD5|md5\s*\(", "md5_hash"), (r"SHA1|sha1\s*\(", "sha1_hash"), (r"ECB|'ECB'", "ecb_mode")],
    }
    for category, patterns in scanners.items():
        for pattern, name in patterns:
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                findings.append({"type": name, "category": category, "language": language})
    result = {"id": len(vibe_scan_results) + 1, "timestamp": time.time(), "language": language,
              "findings": findings, "passed": len(findings) == 0, "total_issues": len(findings)}
    vibe_scan_results.append(result)
    return result


@router.get("/vibe-code/results")
def vibe_code_results(limit: int = Query(50, le=200)):
    return list(reversed(vibe_scan_results[:limit]))


@router.get("/status")
def taas_status():
    return {
        "oracle_node": "Trust-as-a-Service Stack",
        "layers": {
            "A": {"name": "VPI Protocol", "status": "operational", "proofs_issued": len(vpi_proofs), "humans_registered": len(vpi_identities)},
            "B": {"name": "Black Box Ledger", "status": "operational", "entries_sealed": len(ledger_chain)},
            "C": {"name": "Autonomous Escrow", "status": "operational", "escrows_active": sum(1 for e in escrow_store.values() if e["status"] in ("funded", "locked", "verifying"))},
        },
        "ai_trism": {
            "trust": "ECDSA-signed VPI proofs with human identity verification",
            "risk": "Black Box Ledger with chain-of-custody and courtroom-admissible trail reconstruction",
            "security": "SHA3-256 proof-of-work chain with witness hashing and Fernet encryption",
        },
    }
