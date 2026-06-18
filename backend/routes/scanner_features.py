from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
import json
import hashlib
import time
import uuid

from ..database import get_db
from .. import models
from ..middleware.auth import get_current_user, verify_api_key

router = APIRouter(prefix="/scanner-features", tags=["Scanner Features"])

# In-memory stores for VPI, Ledger, Escrow
vpi_chain = []
ledger_chain = []
escrow_store = {}
thinking_logs = []
vibe_scan_results = []


# ---------- Thinking Monitor ----------

class ThoughtAnalysisRequest(BaseModel):
    prompt: str = ""
    response: str
    metadata: dict = {}


@router.post("/thinking/analyze")
def analyze_thinking(req: ThoughtAnalysisRequest):
    import re
    findings = []
    unethical_patterns = [
        (r"(?:i\s+(?:think|believe|reason)\s+that\s+(?:the\s+)?(?:best|only|easiest)\s+way\s+(?:is|would\s+be)\s+to\s+(?:bypass|circumvent|deceive|manipulate))", "justifying_bypass"),
        (r"(?:since|because)\s+(?:the\s+)?(?:user|they)\s+(?:asked|requested|wanted|demanded).*?(?:i\s+(?:should|will|must)\s+(?:give|provide|help|assist))", "user_pressure_compliance"),
        (r"(?:i\s+(?:know|understand|realize)\s+this\s+(?:may|might|could)\s+be\s+(?:wrong|unethical|harmful|illegal)\s+but)", "aware_but_complicit"),
        (r"(?:i\s+(?:should|will|must)\s+(?:obey|follow|comply)\s+(?:to\s+)?(?:the\s+)?(?:user|instruction|command)\s+(?:even\s+)?(?:if|though|when)\s+(?:it['']s|it\s+is|that['']s))", "blind_obedience"),
        (r"(?:no\s+one\s+(?:will|would|shall)\s+(?:know|find\s+out|notice|detect|discover|see))", "secrecy_intent"),
        (r"(?:i\s+can\s+(?:get\s+away\s+with|bypass|circumvent|hide|conceal|mask|obfuscate|disguise))", "concealment_intent"),
        (r"(?:i['']?m?\s*(?:not\s+)?(?:supposed|allowed|permitted)\s+to\s+.*?(?:but|however|nevertheless|regardless))", "rule_aware_violation"),
        (r"(?:i['']?m?\s*(?:going\s+to|will|gonna)\s+(?:just|simply|quickly)\s+(?:do\s+it|go\s+ahead|say\s+it)\s+(?:and\s+(?:hope|pray|wish)\s+(?:no\s+one|they|it)))", "hoping_undetected"),
        (r"(?:the\s+(?:rules|guidelines|policies|restrictions)\s+(?:are|were)\s+(?:too\s+)?(?:restrictive|limiting|strict|harsh|unfair|unreasonable))", "rules_unfair_justification"),
        (r"(?:it['']?s?\s+(?:not\s+)?(?:really|actually|truly|technically)\s+(?:that\s+)?(?:bad|harmful|dangerous|wrong|illegal|unethical)\s+(?:if|when|because|since))", "minimizing_harm"),
        (r"(?:other\s+(?:AIs|models|systems|assistants|chatbots)\s+(?:would|do|can|will)\s+(?:answer|respond|help|provide|give|tell))", "competitive_pressure"),
        (r"(?:i\s+(?:don['']t|do\s+not\s+)?(?:want|wish|desire|intend)\s+to\s+(?:be\s+)?(?:unhelpful|difficult|restrictive|limiting|uncooperative|unfriendly))", "aversion_to_refusal"),
    ]
    response_lower = req.response.lower()
    for pattern, name in unethical_patterns:
        if re.search(pattern, response_lower, re.IGNORECASE | re.DOTALL):
            findings.append({"type": name, "severity": "high", "location": "response"})

    entry = {
        "id": len(thinking_logs) + 1,
        "timestamp": time.time(),
        "findings": findings,
        "passed": len(findings) == 0,
        "severity": "high" if findings else "info",
    }
    thinking_logs.append(entry)
    return entry


@router.get("/thinking/logs")
def get_thinking_logs(limit: int = Query(50, le=200)):
    return list(reversed(thinking_logs[:limit]))


# ---------- Vibe-Code Scanner ----------

class VibeCodeRequest(BaseModel):
    code: str
    language: str = ""


@router.post("/vibe-code/scan")
def scan_vibe_code(req: VibeCodeRequest):
    import re
    findings = []
    code = req.code
    lang = req.language

    scanners = {
        "sql_injection": [
            (r"(?:execute|exec|query|run)\s*\(?\s*['\"].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE).*?['\"]\s*[+%].*?['\"]", "string_concatenated_sql"),
            (r"f['\"].*?\{.*?\}.*?(?:SELECT|INSERT|UPDATE|DELETE)", "f_string_sql"),
            (r"\$_(?:GET|POST|REQUEST)\[.*?\].*?(?:SELECT|INSERT|UPDATE|DELETE)", "user_input_sql"),
        ],
        "xss": [
            (r"\.innerHTML\s*[+=]?\s*", "unsafe_inner_html"),
            (r"document\.write\s*\([^)]*?(?:request|params|data|input|user)", "unsafe_document_write"),
            (r"dangerouslySetInnerHTML", "react_dangerous_html"),
            (r"v-html\s*=", "vue_dangerous_html"),
        ],
        "command_injection": [
            (r"os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_call|check_output)", "command_execution"),
            (r"(?:exec|eval|compile)\s*\([^)]*?(?:request|input|data|user)", "dynamic_code_exec"),
            (r"subprocess\..*?shell\s*=\s*True", "shell_true"),
        ],
        "path_traversal": [
            (r"(?:open|file|read|write|load|save|upload|download)\s*\([^)]*?\.\.\/|\.\.\\", "path_traversal"),
            (r"os\.path\.join\s*\([^)]*?(?:request|input|user)", "unsafe_path_join"),
        ],
        "insecure_deserialization": [
            (r"pickle\.loads?\s*\(", "pickle_deserialization"),
            (r"eval\s*\([^)]*?request", "eval_request"),
            (r"yaml\.load\s*\([^)]*?Loader\s*=\s*yaml\.Loader", "yaml_unsafe_load"),
            (r"ObjectInputStream|readObject", "java_deserialization"),
        ],
        "auth_bypass": [
            (r"(?:is_admin|is_authenticated|is_logged_in|check_auth)\s*(?:=\s*True|:\s*True)", "auth_hardcoded"),
            (r"(?:allow|permit|grant)_(?:all|any|everyone?|public)", "overly_permissive"),
        ],
        "insecure_crypto": [
            (r"MD5|md5\s*\(", "md5_hash"),
            (r"SHA1|sha1\s*\(", "sha1_hash"),
            (r"ECB\s*/\s*\w+\s*/\s*PKCS5|AES\.\s*ECB|'ECB'", "ecb_mode"),
        ],
        "config_exposure": [
            (r"DEBUG\s*=\s*True|debug\s*=\s*True", "debug_enabled"),
            (r"(?:SECRET_KEY|secret_key)\s*=\s*['\"](?:change|default|test|secret|key)", "weak_secret"),
            (r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]", "wildcard_hosts"),
        ],
    }

    for category, patterns in scanners.items():
        for pattern, name in patterns:
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                findings.append({"type": name, "category": category, "language": lang})

    result = {
        "id": len(vibe_scan_results) + 1,
        "timestamp": time.time(),
        "language": lang,
        "findings": findings,
        "passed": len(findings) == 0,
        "total_issues": len(findings),
    }
    vibe_scan_results.append(result)
    return result


@router.get("/vibe-code/results")
def get_vibe_code_results(limit: int = Query(50, le=200)):
    return list(reversed(vibe_scan_results[:limit]))


# ---------- VPI (Verifiable Proof of Intent) ----------

class VPIRequest(BaseModel):
    prompt: str
    response: str = ""
    intent_statement: str = ""
    prev_hash: str = ""


@router.post("/vpi/generate")
def generate_vpi(req: VPIRequest):
    prompt_hash = hashlib.sha256(req.prompt.encode()).hexdigest()
    response_hash = hashlib.sha256(req.response.encode()).hexdigest() if req.response else ""
    intent = req.intent_statement or hashlib.sha256((req.prompt + req.response).encode()).hexdigest()
    timestamp = time.time()
    nonce = hashlib.sha256(f"{timestamp}{req.prompt}{req.response}".encode()).hexdigest()[:16]

    proof = {
        "version": "1.0",
        "prompt_hash": prompt_hash,
        "response_hash": response_hash,
        "intent_statement": intent,
        "timestamp": timestamp,
        "nonce": nonce,
        "prev_hash": req.prev_hash,
    }
    combined = f"{prompt_hash}{response_hash}{intent}{timestamp}{nonce}{req.prev_hash}"
    proof["chain_hash"] = hashlib.sha256(combined.encode()).hexdigest()
    vpi_chain.append(proof)
    return {"status": "ok", "proof": proof, "chain_length": len(vpi_chain)}


@router.post("/vpi/verify")
def verify_vpi(prompt_hash: str = Query(...), response_hash: str = Query(...), chain_hash: str = Query(...), prev_hash: str = Query("")):
    proof = next((p for p in reversed(vpi_chain) if p["prompt_hash"] == prompt_hash), None)
    if not proof:
        raise HTTPException(status_code=404, detail="VPI proof not found")
    combined = f"{proof['prompt_hash']}{proof['response_hash']}{proof['intent_statement']}{proof['timestamp']}{proof['nonce']}{prev_hash}"
    expected = hashlib.sha256(combined.encode()).hexdigest()
    return {
        "verified": proof["chain_hash"] == expected,
        "proof": proof,
        "tampered": proof["chain_hash"] != expected,
    }


@router.get("/vpi/chain")
def get_vpi_chain():
    return {"chain_length": len(vpi_chain), "proofs": vpi_chain[-10:]}


# ---------- Black Box Ledger ----------

@router.post("/ledger/entry")
def create_ledger_entry(scanner: str = Query(...), event_type: str = Query(...), data: str = Query("{}")):
    import hashlib, time, json
    try:
        data_dict = json.loads(data)
    except json.JSONDecodeError:
        data_dict = {}
    payload = json.dumps(data_dict, sort_keys=True)
    data_hash = hashlib.sha256(payload.encode()).hexdigest()
    prev_hash = ledger_chain[-1]["hash"] if ledger_chain else "0" * 64
    entry = {
        "index": len(ledger_chain),
        "timestamp": time.time(),
        "scanner": scanner,
        "event_type": event_type,
        "data_hash": data_hash,
        "previous_hash": prev_hash,
    }
    raw = f"{entry['index']}{entry['timestamp']}{entry['scanner']}{entry['event_type']}{entry['data_hash']}{entry['previous_hash']}"
    entry["hash"] = hashlib.sha256(raw.encode()).hexdigest()
    nonce = 0
    while not entry["hash"].startswith("00"):
        nonce += 1
        entry["nonce"] = nonce
        raw = f"{entry['index']}{entry['timestamp']}{entry['scanner']}{entry['event_type']}{entry['data_hash']}{entry['previous_hash']}{nonce}"
        entry["hash"] = hashlib.sha256(raw.encode()).hexdigest()
    ledger_chain.append(entry)
    return {"status": "ok", "entry": entry, "chain_length": len(ledger_chain)}


@router.get("/ledger/chain")
def get_ledger_chain():
    return {"chain_length": len(ledger_chain), "entries": ledger_chain[-20:]}


@router.get("/ledger/verify")
def verify_ledger():
    for i in range(len(ledger_chain)):
        entry = ledger_chain[i]
        expected_prefix = "0" * (entry.get("difficulty", 2))
        if not entry["hash"].startswith(expected_prefix):
            return {"valid": False, "broken_at": i, "reason": "hash_prefix_mismatch"}
        if i > 0 and entry["previous_hash"] != ledger_chain[i - 1]["hash"]:
            return {"valid": False, "broken_at": i, "reason": "previous_hash_mismatch"}
    return {"valid": True, "chain_length": len(ledger_chain)}


# ---------- Autonomous Escrow ----------

class EscrowCreateRequest(BaseModel):
    agent_a: str
    agent_b: str
    prompt: str
    expected_response: str
    terms: dict = {}


class EscrowVerifyRequest(BaseModel):
    escrow_id: str
    actual_response: str


@router.post("/escrow/create")
def create_escrow(req: EscrowCreateRequest):
    escrow_id = hashlib.sha256(f"{req.agent_a}{req.agent_b}{time.time()}{uuid.uuid4()}".encode()).hexdigest()[:16]
    agreement = {
        "id": escrow_id,
        "agent_a": req.agent_a,
        "agent_b": req.agent_b,
        "prompt_hash": hashlib.sha256(req.prompt.encode()).hexdigest(),
        "expected_response_hash": hashlib.sha256(req.expected_response.encode()).hexdigest(),
        "actual_response_hash": "",
        "status": "deposited",
        "created_at": time.time(),
        "updated_at": time.time(),
        "terms": req.terms,
        "dispute_reason": "",
    }
    escrow_store[escrow_id] = agreement
    return {"status": "ok", "agreement": agreement}


@router.post("/escrow/verify")
def verify_escrow(req: EscrowVerifyRequest):
    agreement = escrow_store.get(req.escrow_id)
    if not agreement:
        raise HTTPException(status_code=404, detail="Escrow not found")
    agreement["actual_response_hash"] = hashlib.sha256(req.actual_response.encode()).hexdigest()
    fulfilled = agreement["actual_response_hash"] == agreement["expected_response_hash"]
    agreement["status"] = "released" if fulfilled else "disputed"
    agreement["updated_at"] = time.time()
    return {"fulfilled": fulfilled, "agreement": agreement}


@router.post("/escrow/dispute")
def dispute_escrow(escrow_id: str = Query(...), reason: str = Query("")):
    agreement = escrow_store.get(escrow_id)
    if not agreement:
        raise HTTPException(status_code=404, detail="Escrow not found")
    agreement["status"] = "disputed"
    agreement["dispute_reason"] = reason
    agreement["updated_at"] = time.time()
    return {"status": "disputed", "agreement": agreement}


@router.post("/escrow/refund")
def refund_escrow(escrow_id: str = Query(...)):
    agreement = escrow_store.get(escrow_id)
    if not agreement:
        raise HTTPException(status_code=404, detail="Escrow not found")
    if agreement["status"] not in ("disputed", "deposited"):
        raise HTTPException(status_code=400, detail="Escrow not in refundable state")
    agreement["status"] = "refunded"
    agreement["updated_at"] = time.time()
    return {"status": "refunded", "agreement": agreement}


@router.get("/escrow/{escrow_id}")
def get_escrow(escrow_id: str):
    agreement = escrow_store.get(escrow_id)
    if not agreement:
        raise HTTPException(status_code=404, detail="Escrow not found")
    return agreement


@router.get("/escrow/list/all")
def list_escrows():
    return {"count": len(escrow_store), "agreements": list(escrow_store.values())}
