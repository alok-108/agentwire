//! PyO3 Python bindings exposing the AgentWire Rust binary codec, HMAC-SHA256 frame
//! authentication, deterministic policy & replay guard-gate engine, two-phase budget
//! ledger, and lossless decompiler to Python as `agentwire._agentwire`.

use std::collections::BTreeMap;
use std::sync::Mutex;

use agentwire_core::{
    decompile_ast, decompile_frame as core_decompile_frame, decode_frame as core_decode_frame,
    encode_frame as core_encode_frame, generate_ed25519_keypair as core_generate_ed25519_keypair,
    sign_frame as core_sign_frame, sign_frame_ed25519 as core_sign_frame_ed25519,
    verify_and_decode_ed25519 as core_verify_and_decode_ed25519,
    verify_and_decode_frame as core_verify_and_decode_frame, AgentAction, AstNode, AstValue,
    BudgetCap, FrameFlags, FrameHeader, WireFrame, ED25519_KEY_LEN, ED25519_SIG_LEN, HMAC_TAG_LEN,
    MAGIC_BYTES, PROTOCOL_VERSION, STATIC_DICT,
};
use agentwire_validator::{PolicyEngine as CorePolicyEngine, ValidationResult};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString};

fn py_to_ast_value(obj: &Bound<'_, PyAny>) -> PyResult<AstValue> {
    if obj.is_none() {
        return Ok(AstValue::Null);
    }
    if obj.is_instance_of::<PyBool>() {
        return Ok(AstValue::Bool(obj.extract::<bool>()?));
    }
    if obj.is_instance_of::<PyInt>() {
        return Ok(AstValue::Int(obj.extract::<i64>()?));
    }
    if obj.is_instance_of::<PyFloat>() {
        return Ok(AstValue::Float(obj.extract::<f64>()?));
    }
    if obj.is_instance_of::<PyString>() {
        return Ok(AstValue::String(obj.extract::<String>()?));
    }
    if let Ok(list) = obj.downcast::<PyList>() {
        let mut out = Vec::with_capacity(list.len());
        for item in list.iter() {
            out.push(py_to_ast_value(&item)?);
        }
        return Ok(AstValue::List(out));
    }
    if let Ok(dict) = obj.downcast::<PyDict>() {
        if dict.len() == 1 {
            if let Some(ref_val) = dict.get_item("$ref")? {
                if let Ok(uri) = ref_val.extract::<String>() {
                    return Ok(AstValue::Ref(uri));
                }
            }
        }
        let mut map = BTreeMap::new();
        for (k, v) in dict.iter() {
            let key: String = k.extract()?;
            let val = py_to_ast_value(&v)?;
            map.insert(key, val);
        }
        return Ok(AstValue::Map(map));
    }
    Err(PyValueError::new_err(format!(
        "unsupported AST value type: {}",
        obj.get_type().name()?
    )))
}

fn ast_value_to_py<'py>(py: Python<'py>, value: &AstValue) -> PyResult<Bound<'py, PyAny>> {
    match value {
        AstValue::Null => Ok(py.None().into_bound(py)),
        AstValue::Bool(b) => Ok(PyBool::new(py, *b).to_owned().into_any()),
        AstValue::Int(i) => Ok(i.into_pyobject(py)?.into_any()),
        AstValue::Float(f) => Ok(f.into_pyobject(py)?.into_any()),
        AstValue::String(s) => Ok(PyString::new(py, s).into_any()),
        AstValue::List(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(ast_value_to_py(py, item)?)?;
            }
            Ok(list.into_any())
        }
        AstValue::Map(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                dict.set_item(k, ast_value_to_py(py, v)?)?;
            }
            Ok(dict.into_any())
        }
        AstValue::Ref(uri) => {
            let dict = PyDict::new(py);
            dict.set_item("$ref", uri)?;
            Ok(dict.into_any())
        }
    }
}

fn py_dict_to_payload(payload: Option<&Bound<'_, PyDict>>) -> PyResult<BTreeMap<String, AstValue>> {
    let mut map = BTreeMap::new();
    if let Some(dict) = payload {
        for (k, v) in dict.iter() {
            let key: String = k.extract()?;
            let val = py_to_ast_value(&v)?;
            map.insert(key, val);
        }
    }
    Ok(map)
}

fn frame_to_py_dict<'py>(py: Python<'py>, frame: &WireFrame) -> PyResult<Bound<'py, PyDict>> {
    let header = PyDict::new(py);
    header.set_item("version", frame.header.version)?;
    header.set_item("flags", frame.header.flags)?;
    header.set_item("trace_id", frame.header.trace_id)?;
    header.set_item("span_id", frame.header.span_id)?;
    header.set_item("hop_depth", frame.header.hop_depth)?;
    header.set_item("nonce", frame.header.nonce)?;
    header.set_item("timestamp_ms", frame.header.timestamp_ms)?;
    header.set_item("source_agent", &frame.header.source_agent)?;
    header.set_item("target_agent", &frame.header.target_agent)?;
    header.set_item("max_tokens", frame.header.budget.max_tokens)?;
    header.set_item("max_micro_usd", frame.header.budget.max_micro_usd)?;
    header.set_item(
        "guard_verified",
        (frame.header.flags & FrameFlags::GUARD_VERIFIED) != 0,
    )?;
    header.set_item(
        "authenticated",
        (frame.header.flags & (FrameFlags::AUTHENTICATED | FrameFlags::SIGNED_ED25519)) != 0,
    )?;
    header.set_item(
        "signed_ed25519",
        (frame.header.flags & FrameFlags::SIGNED_ED25519) != 0,
    )?;
    header.set_item("mac_verified", frame.header.mac_verified)?;

    let payload = PyDict::new(py);
    for (k, v) in &frame.body.payload {
        payload.set_item(k, ast_value_to_py(py, v)?)?;
    }

    let body = PyDict::new(py);
    body.set_item("action", frame.body.action.as_str())?;
    body.set_item("target", &frame.body.target)?;
    body.set_item("intent", &frame.body.intent)?;
    body.set_item("payload", payload)?;
    body.set_item("refs", &frame.body.refs)?;

    let out = PyDict::new(py);
    out.set_item("header", header)?;
    out.set_item("body", body)?;
    Ok(out)
}

fn validation_result_to_py<'py>(
    py: Python<'py>,
    res: &ValidationResult,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    match res {
        ValidationResult::Allowed => {
            dict.set_item("allowed", true)?;
            dict.set_item("reason_code", py.None())?;
            dict.set_item("detail", py.None())?;
        }
        ValidationResult::Rejected {
            reason_code,
            detail,
        } => {
            dict.set_item("allowed", false)?;
            dict.set_item("reason_code", reason_code.as_str())?;
            dict.set_item("detail", detail.as_str())?;
        }
    }
    Ok(dict)
}

#[allow(clippy::too_many_arguments)]
fn build_frame(
    source_agent: &str,
    target_agent: &str,
    action: &str,
    target: &str,
    intent: &str,
    payload: Option<&Bound<'_, PyDict>>,
    refs: Option<Vec<String>>,
    trace_id: u64,
    span_id: u32,
    hop_depth: u16,
    max_tokens: u32,
    max_micro_usd: u64,
    guard_verified: bool,
    nonce: u64,
    timestamp_ms: u64,
) -> PyResult<WireFrame> {
    let parsed_action =
        AgentAction::parse_name(action).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let payload_map = py_dict_to_payload(payload)?;

    let mut header = FrameHeader::new(source_agent, target_agent, trace_id, span_id);
    header.hop_depth = hop_depth;
    header.nonce = nonce;
    header.timestamp_ms = timestamp_ms;
    header.budget = BudgetCap {
        max_tokens,
        max_micro_usd,
    };
    if guard_verified {
        header.flags |= FrameFlags::GUARD_VERIFIED;
    }

    let body = AstNode {
        action: parsed_action,
        target: target.to_string(),
        intent: intent.to_string(),
        payload: payload_map,
        refs: refs.unwrap_or_default(),
    };
    Ok(WireFrame::new(header, body))
}

/// Encode an unsigned typed AgentWire AST message into a compact binary wire frame (`AW01` + CRC32).
#[pyfunction]
#[pyo3(signature = (
    source_agent,
    target_agent,
    action,
    target,
    intent,
    payload=None,
    refs=None,
    trace_id=1,
    span_id=1,
    hop_depth=0,
    max_tokens=2048,
    max_micro_usd=50_000,
    guard_verified=false
))]
#[allow(clippy::too_many_arguments)]
fn encode_ast<'py>(
    py: Python<'py>,
    source_agent: &str,
    target_agent: &str,
    action: &str,
    target: &str,
    intent: &str,
    payload: Option<&Bound<'py, PyDict>>,
    refs: Option<Vec<String>>,
    trace_id: u64,
    span_id: u32,
    hop_depth: u16,
    max_tokens: u32,
    max_micro_usd: u64,
    guard_verified: bool,
) -> PyResult<Bound<'py, PyBytes>> {
    let frame = build_frame(
        source_agent,
        target_agent,
        action,
        target,
        intent,
        payload,
        refs,
        trace_id,
        span_id,
        hop_depth,
        max_tokens,
        max_micro_usd,
        guard_verified,
        0,
        0,
    )?;
    let encoded = core_encode_frame(&frame).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &encoded))
}

/// Encode and cryptographically sign an AgentWire AST message using HMAC-SHA256 + replay nonce/timestamp.
#[pyfunction]
#[pyo3(signature = (
    source_agent,
    target_agent,
    action,
    target,
    intent,
    signing_key,
    nonce,
    timestamp_ms,
    payload=None,
    refs=None,
    trace_id=1,
    span_id=1,
    hop_depth=0,
    max_tokens=2048,
    max_micro_usd=50_000,
    guard_verified=false
))]
#[allow(clippy::too_many_arguments)]
fn sign_ast<'py>(
    py: Python<'py>,
    source_agent: &str,
    target_agent: &str,
    action: &str,
    target: &str,
    intent: &str,
    signing_key: &[u8],
    nonce: u64,
    timestamp_ms: u64,
    payload: Option<&Bound<'py, PyDict>>,
    refs: Option<Vec<String>>,
    trace_id: u64,
    span_id: u32,
    hop_depth: u16,
    max_tokens: u32,
    max_micro_usd: u64,
    guard_verified: bool,
) -> PyResult<Bound<'py, PyBytes>> {
    let frame = build_frame(
        source_agent,
        target_agent,
        action,
        target,
        intent,
        payload,
        refs,
        trace_id,
        span_id,
        hop_depth,
        max_tokens,
        max_micro_usd,
        guard_verified,
        nonce,
        timestamp_ms,
    )?;
    let encoded =
        core_sign_frame(&frame, signing_key).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &encoded))
}

/// Decode and CRC32-verify a binary AgentWire frame without verifying HMAC (`mac_verified=False`).
#[pyfunction]
fn decode_frame<'py>(py: Python<'py>, raw_bytes: &[u8]) -> PyResult<Bound<'py, PyDict>> {
    let frame =
        core_decode_frame(raw_bytes).map_err(|e| PyValueError::new_err(e.to_string()))?;
    frame_to_py_dict(py, &frame)
}

/// Cryptographically verify HMAC-SHA256 (constant-time) and decode a signed AgentWire frame.
#[pyfunction]
fn verify_frame<'py>(
    py: Python<'py>,
    raw_bytes: &[u8],
    signing_key: &[u8],
) -> PyResult<Bound<'py, PyDict>> {
    let frame = core_verify_and_decode_frame(raw_bytes, signing_key)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    frame_to_py_dict(py, &frame)
}

fn py_dict_to_pubkeys(
    public_keys: &Bound<'_, PyDict>,
) -> PyResult<BTreeMap<String, [u8; ED25519_KEY_LEN]>> {
    let mut map = BTreeMap::new();
    for (k, v) in public_keys.iter() {
        let agent: String = k.extract()?;
        let raw: Vec<u8> = v.extract()?;
        let arr: [u8; ED25519_KEY_LEN] = raw.try_into().map_err(|_| {
            PyValueError::new_err(format!(
                "Ed25519 public key for '{}' must be exactly {} bytes",
                agent, ED25519_KEY_LEN
            ))
        })?;
        map.insert(agent, arr);
    }
    Ok(map)
}

fn decode_with_optional_auth(
    raw_bytes: &[u8],
    signing_key: Option<&[u8]>,
    public_keys: Option<&Bound<'_, PyDict>>,
) -> PyResult<WireFrame> {
    if let Some(pk_dict) = public_keys {
        let registry = py_dict_to_pubkeys(pk_dict)?;
        return core_verify_and_decode_ed25519(raw_bytes, &registry)
            .map_err(|e| PyValueError::new_err(e.to_string()));
    }
    if let Some(key) = signing_key {
        return core_verify_and_decode_frame(raw_bytes, key)
            .map_err(|e| PyValueError::new_err(e.to_string()));
    }
    core_decode_frame(raw_bytes).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Generate a fresh 32-byte Ed25519 `(private_key, public_key)` pair using the OS CSPRNG.
#[pyfunction]
fn generate_ed25519_keypair<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (priv_k, pub_k) =
        core_generate_ed25519_keypair().map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok((PyBytes::new(py, &priv_k), PyBytes::new(py, &pub_k)))
}

/// Encode and asymmetrically sign an AgentWire AST frame using the sender's 32-byte Ed25519 private key.
#[pyfunction]
#[pyo3(signature = (
    source_agent,
    target_agent,
    action,
    target,
    intent,
    private_key,
    nonce,
    timestamp_ms,
    payload=None,
    refs=None,
    trace_id=1,
    span_id=1,
    hop_depth=0,
    max_tokens=2048,
    max_micro_usd=50_000,
    guard_verified=false
))]
#[allow(clippy::too_many_arguments)]
fn sign_ast_ed25519<'py>(
    py: Python<'py>,
    source_agent: &str,
    target_agent: &str,
    action: &str,
    target: &str,
    intent: &str,
    private_key: &[u8],
    nonce: u64,
    timestamp_ms: u64,
    payload: Option<&Bound<'py, PyDict>>,
    refs: Option<Vec<String>>,
    trace_id: u64,
    span_id: u32,
    hop_depth: u16,
    max_tokens: u32,
    max_micro_usd: u64,
    guard_verified: bool,
) -> PyResult<Bound<'py, PyBytes>> {
    let frame = build_frame(
        source_agent,
        target_agent,
        action,
        target,
        intent,
        payload,
        refs,
        trace_id,
        span_id,
        hop_depth,
        max_tokens,
        max_micro_usd,
        guard_verified,
        nonce,
        timestamp_ms,
    )?;
    let encoded = core_sign_frame_ed25519(&frame, private_key)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &encoded))
}

/// Cryptographically verify an Ed25519-signed frame strictly against `public_keys[source_agent]`.
#[pyfunction]
fn verify_frame_ed25519<'py>(
    py: Python<'py>,
    raw_bytes: &[u8],
    public_keys: &Bound<'py, PyDict>,
) -> PyResult<Bound<'py, PyDict>> {
    let registry = py_dict_to_pubkeys(public_keys)?;
    let frame = core_verify_and_decode_ed25519(raw_bytes, &registry)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    frame_to_py_dict(py, &frame)
}

/// Stateless single-frame policy validation (with optional HMAC or Ed25519 verification & clock skew check).
#[pyfunction]
#[pyo3(signature = (raw_bytes, policy_json=None, signing_key=None, now_ms=None, public_keys=None))]
fn validate_frame<'py>(
    py: Python<'py>,
    raw_bytes: &[u8],
    policy_json: Option<&str>,
    signing_key: Option<&[u8]>,
    now_ms: Option<u64>,
    public_keys: Option<&Bound<'py, PyDict>>,
) -> PyResult<Bound<'py, PyDict>> {
    let frame = decode_with_optional_auth(raw_bytes, signing_key, public_keys)?;

    let engine = match policy_json {
        Some(json) => CorePolicyEngine::from_json(json)
            .map_err(|e| PyValueError::new_err(e.to_string()))?,
        None => CorePolicyEngine::default_multi_agent(),
    };

    let result = engine.validate_frame_at(&frame, now_ms);
    validation_result_to_py(py, &result)
}

/// Losslessly decompile a binary AgentWire frame into a human-readable trace summary dictionary.
#[pyfunction]
#[pyo3(signature = (raw_bytes, signing_key=None, public_keys=None))]
fn decompile_frame<'py>(
    py: Python<'py>,
    raw_bytes: &[u8],
    signing_key: Option<&[u8]>,
    public_keys: Option<&Bound<'py, PyDict>>,
) -> PyResult<Bound<'py, PyDict>> {
    let frame = decode_with_optional_auth(raw_bytes, signing_key, public_keys)?;
    let summary = core_decompile_frame(&frame);

    let out = PyDict::new(py);
    out.set_item("trace_id", summary.trace_id)?;
    out.set_item("span_id", summary.span_id)?;
    out.set_item("hop_depth", summary.hop_depth)?;
    out.set_item("nonce", summary.nonce)?;
    out.set_item("timestamp_ms", summary.timestamp_ms)?;
    out.set_item("source_agent", summary.source_agent)?;
    out.set_item("target_agent", summary.target_agent)?;
    out.set_item("action", summary.action)?;
    out.set_item("target", summary.target)?;
    out.set_item("intent", summary.intent)?;
    out.set_item("budget_tokens", summary.budget_tokens)?;
    out.set_item("budget_usd", summary.budget_usd)?;
    out.set_item("guard_verified", summary.guard_verified)?;
    out.set_item("authenticated", summary.authenticated)?;
    out.set_item("mac_verified", summary.mac_verified)?;
    out.set_item("human_readable", summary.human_readable)?;
    out.set_item("canonical_ast", summary.canonical_ast)?;
    out.set_item("structured_lines", summary.structured_lines)?;
    Ok(out)
}

#[pyfunction]
#[pyo3(signature = (action, target, intent, payload=None, refs=None))]
fn decompile_ast_dict(
    action: &str,
    target: &str,
    intent: &str,
    payload: Option<&Bound<'_, PyDict>>,
    refs: Option<Vec<String>>,
) -> PyResult<String> {
    let parsed_action =
        AgentAction::parse_name(action).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let node = AstNode {
        action: parsed_action,
        target: target.to_string(),
        intent: intent.to_string(),
        payload: py_dict_to_payload(payload)?,
        refs: refs.unwrap_or_default(),
    };
    Ok(decompile_ast(&node))
}

#[pyfunction]
fn protocol_info<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);
    out.set_item("magic", std::str::from_utf8(&MAGIC_BYTES).unwrap_or("AW01"))?;
    out.set_item("version", PROTOCOL_VERSION)?;
    out.set_item("static_dict_size", STATIC_DICT.len())?;
    out.set_item("hmac_tag_bytes", HMAC_TAG_LEN)?;
    out.set_item("ed25519_sig_bytes", ED25519_SIG_LEN)?;
    Ok(out)
}

/// Thread-safe deterministic Rust guard-gate engine with replay detection & two-phase budget ledger.
#[pyclass(name = "PolicyEngine")]
struct PyPolicyEngine {
    inner: Mutex<CorePolicyEngine>,
}

#[pymethods]
impl PyPolicyEngine {
    #[new]
    #[pyo3(signature = (policy_json=None))]
    fn new(policy_json: Option<&str>) -> PyResult<Self> {
        let engine = match policy_json {
            Some(json) => CorePolicyEngine::from_json(json)
                .map_err(|e| PyValueError::new_err(e.to_string()))?,
            None => CorePolicyEngine::default_multi_agent(),
        };
        Ok(Self {
            inner: Mutex::new(engine),
        })
    }

    #[staticmethod]
    fn default_multi_agent() -> Self {
        Self {
            inner: Mutex::new(CorePolicyEngine::default_multi_agent()),
        }
    }

    #[staticmethod]
    fn strict_authenticated() -> Self {
        Self {
            inner: Mutex::new(CorePolicyEngine::strict_authenticated()),
        }
    }

    #[staticmethod]
    fn from_json(policy_json: &str) -> PyResult<Self> {
        let engine = CorePolicyEngine::from_json(policy_json)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self {
            inner: Mutex::new(engine),
        })
    }

    fn to_json(&self) -> PyResult<String> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| PyValueError::new_err("PolicyEngine mutex poisoned"))?;
        guard
            .spec()
            .to_json()
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Pure read-only validation of a binary frame (optionally verifying HMAC-SHA256 or Ed25519 & clock skew).
    #[pyo3(signature = (raw_bytes, signing_key=None, now_ms=None, public_keys=None))]
    fn validate_frame<'py>(
        &self,
        py: Python<'py>,
        raw_bytes: &[u8],
        signing_key: Option<&[u8]>,
        now_ms: Option<u64>,
        public_keys: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let frame = decode_with_optional_auth(raw_bytes, signing_key, public_keys)?;
        let guard = self
            .inner
            .lock()
            .map_err(|_| PyValueError::new_err("PolicyEngine mutex poisoned"))?;
        let res = guard.validate_frame_at(&frame, now_ms);
        validation_result_to_py(py, &res)
    }

    /// Phase 1 (Reserve): evaluate invariants, verify HMAC or Ed25519 if supplied, reserve budget,
    /// and record replay nonce + hop signature on acceptance.
    #[pyo3(signature = (raw_bytes, signing_key=None, now_ms=None, public_keys=None))]
    fn evaluate_and_record<'py>(
        &self,
        py: Python<'py>,
        raw_bytes: &[u8],
        signing_key: Option<&[u8]>,
        now_ms: Option<u64>,
        public_keys: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let frame = decode_with_optional_auth(raw_bytes, signing_key, public_keys)?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PyValueError::new_err("PolicyEngine mutex poisoned"))?;
        let res = guard.evaluate_and_record_at(&frame, now_ms);
        validation_result_to_py(py, &res)
    }

    /// Phase 2 (Settle): finalize an active reservation with actual downstream token & cost usage.
    fn settle_usage<'py>(
        &self,
        py: Python<'py>,
        trace_id: u64,
        span_id: u32,
        actual_tokens: u32,
        actual_micro_usd: u64,
    ) -> PyResult<Bound<'py, PyDict>> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PyValueError::new_err("PolicyEngine mutex poisoned"))?;
        let receipt = guard
            .settle_usage(trace_id, span_id, actual_tokens, actual_micro_usd)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let out = PyDict::new(py);
        out.set_item("trace_id", receipt.trace_id)?;
        out.set_item("span_id", receipt.span_id)?;
        out.set_item("reserved_tokens", receipt.reserved_tokens)?;
        out.set_item("actual_tokens", receipt.actual_tokens)?;
        out.set_item("released_tokens", receipt.released_tokens)?;
        out.set_item("reserved_micro_usd", receipt.reserved_micro_usd)?;
        out.set_item("actual_micro_usd", receipt.actual_micro_usd)?;
        out.set_item("released_micro_usd", receipt.released_micro_usd)?;
        Ok(out)
    }

    /// Phase 2 (Release): cancel an active reservation and refund 100% back to the session budget.
    fn release_reservation<'py>(
        &self,
        py: Python<'py>,
        trace_id: u64,
        span_id: u32,
    ) -> PyResult<Bound<'py, PyDict>> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PyValueError::new_err("PolicyEngine mutex poisoned"))?;
        let refunded = guard
            .release_reservation(trace_id, span_id)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let out = PyDict::new(py);
        out.set_item("trace_id", refunded.trace_id)?;
        out.set_item("span_id", refunded.span_id)?;
        out.set_item("reserved_tokens", refunded.reserved_tokens)?;
        out.set_item("reserved_micro_usd", refunded.reserved_micro_usd)?;
        Ok(out)
    }

    /// Return full two-phase budget ledger snapshot (settled, active reserved, and remaining).
    fn budget_ledger<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| PyValueError::new_err("PolicyEngine mutex poisoned"))?;
        let ledger = guard.budget_ledger();
        let out = PyDict::new(py);
        out.set_item("session_max_tokens", ledger.session_max_tokens)?;
        out.set_item("session_max_micro_usd", ledger.session_max_micro_usd)?;
        out.set_item("settled_tokens", ledger.settled_tokens)?;
        out.set_item("settled_micro_usd", ledger.settled_micro_usd)?;
        out.set_item("reserved_tokens", ledger.reserved_tokens)?;
        out.set_item("reserved_micro_usd", ledger.reserved_micro_usd)?;
        out.set_item("remaining_tokens", ledger.remaining_tokens)?;
        out.set_item("remaining_micro_usd", ledger.remaining_micro_usd)?;
        out.set_item("active_reservations", ledger.active_reservations)?;
        out.set_item("evaluated_frames", ledger.evaluated_frames)?;
        out.set_item("rejected_frames", ledger.rejected_frames)?;
        Ok(out)
    }

    /// Backwards-compatible summary of remaining budget and evaluation counters.
    fn remaining_budget<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        self.budget_ledger(py)
    }

    fn reset(&self) -> PyResult<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PyValueError::new_err("PolicyEngine mutex poisoned"))?;
        guard.reset_session();
        Ok(())
    }
}

#[pymodule]
fn _agentwire(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encode_ast, m)?)?;
    m.add_function(wrap_pyfunction!(sign_ast, m)?)?;
    m.add_function(wrap_pyfunction!(generate_ed25519_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(sign_ast_ed25519, m)?)?;
    m.add_function(wrap_pyfunction!(decode_frame, m)?)?;
    m.add_function(wrap_pyfunction!(verify_frame, m)?)?;
    m.add_function(wrap_pyfunction!(verify_frame_ed25519, m)?)?;
    m.add_function(wrap_pyfunction!(validate_frame, m)?)?;
    m.add_function(wrap_pyfunction!(decompile_frame, m)?)?;
    m.add_function(wrap_pyfunction!(decompile_ast_dict, m)?)?;
    m.add_function(wrap_pyfunction!(protocol_info, m)?)?;
    m.add_class::<PyPolicyEngine>()?;
    Ok(())
}
