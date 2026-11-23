//! PyO3 Python bindings exposing the AgentWire Rust binary codec, deterministic policy
//! guard-gate engine, and lossless decompiler to Python as `agentwire._agentwire`.

use std::collections::BTreeMap;

use agentwire_core::{
    decompile_ast, decompile_frame as core_decompile_frame, decode_frame as core_decode_frame,
    encode_frame as core_encode_frame, AgentAction, AstNode, AstValue, BudgetCap, FrameFlags,
    FrameHeader, WireFrame, MAGIC_BYTES, PROTOCOL_VERSION, STATIC_DICT,
};
use agentwire_validator::{PolicyEngine as CorePolicyEngine, ValidationResult};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString};

/// Convert an arbitrary Python value into a strictly typed [`AstValue`].
///
/// Convention: a single-key dict `{"$ref": "<uri>"}` is converted into [`AstValue::Ref`].
fn py_to_ast_value(obj: &Bound<'_, PyAny>) -> PyResult<AstValue> {
    if obj.is_none() {
        return Ok(AstValue::Null);
    }
    // Check bool before int because `bool` subclasses `int` in Python.
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

/// Convert a typed [`AstValue`] back into a native Python object.
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

/// Encode a typed AgentWire AST message into a compact binary wire frame (`AW01` + CRC32).
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
    let parsed_action =
        AgentAction::parse_name(action).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let payload_map = py_dict_to_payload(payload)?;

    let mut header = FrameHeader::new(source_agent, target_agent, trace_id, span_id);
    header.hop_depth = hop_depth;
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

    let frame = WireFrame::new(header, body);
    let encoded = core_encode_frame(&frame).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &encoded))
}

/// Decode and CRC32-verify a binary AgentWire frame into a structured Python dictionary.
#[pyfunction]
fn decode_frame<'py>(py: Python<'py>, raw_bytes: &[u8]) -> PyResult<Bound<'py, PyDict>> {
    let frame =
        core_decode_frame(raw_bytes).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let header = PyDict::new(py);
    header.set_item("version", frame.header.version)?;
    header.set_item("flags", frame.header.flags)?;
    header.set_item("trace_id", frame.header.trace_id)?;
    header.set_item("span_id", frame.header.span_id)?;
    header.set_item("hop_depth", frame.header.hop_depth)?;
    header.set_item("source_agent", &frame.header.source_agent)?;
    header.set_item("target_agent", &frame.header.target_agent)?;
    header.set_item("max_tokens", frame.header.budget.max_tokens)?;
    header.set_item("max_micro_usd", frame.header.budget.max_micro_usd)?;
    header.set_item(
        "guard_verified",
        (frame.header.flags & FrameFlags::GUARD_VERIFIED) != 0,
    )?;

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

/// Validate a binary AgentWire frame against the default multi-agent policy or custom JSON policy.
#[pyfunction]
#[pyo3(signature = (raw_bytes, policy_json=None))]
fn validate_frame<'py>(
    py: Python<'py>,
    raw_bytes: &[u8],
    policy_json: Option<&str>,
) -> PyResult<Bound<'py, PyDict>> {
    let frame =
        core_decode_frame(raw_bytes).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let engine = match policy_json {
        Some(json) => CorePolicyEngine::from_json(json)
            .map_err(|e| PyValueError::new_err(e.to_string()))?,
        None => CorePolicyEngine::default_multi_agent(),
    };

    let result = engine.validate_frame(&frame);
    validation_result_to_py(py, &result)
}

/// Losslessly decompile a binary AgentWire frame into a human-readable trace summary dictionary.
#[pyfunction]
fn decompile_frame<'py>(py: Python<'py>, raw_bytes: &[u8]) -> PyResult<Bound<'py, PyDict>> {
    let frame =
        core_decode_frame(raw_bytes).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let summary = core_decompile_frame(&frame);

    let out = PyDict::new(py);
    out.set_item("trace_id", summary.trace_id)?;
    out.set_item("span_id", summary.span_id)?;
    out.set_item("hop_depth", summary.hop_depth)?;
    out.set_item("source_agent", summary.source_agent)?;
    out.set_item("target_agent", summary.target_agent)?;
    out.set_item("action", summary.action)?;
    out.set_item("target", summary.target)?;
    out.set_item("intent", summary.intent)?;
    out.set_item("budget_tokens", summary.budget_tokens)?;
    out.set_item("budget_usd", summary.budget_usd)?;
    out.set_item("guard_verified", summary.guard_verified)?;
    out.set_item("human_readable", summary.human_readable)?;
    out.set_item("canonical_ast", summary.canonical_ast)?;
    out.set_item("structured_lines", summary.structured_lines)?;
    Ok(out)
}

/// Losslessly project AST components directly into a canonical human-readable AST string.
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

/// Return static protocol metadata (magic bytes, version, dictionary size).
#[pyfunction]
fn protocol_info<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);
    out.set_item(
        "magic",
        std::str::from_utf8(&MAGIC_BYTES).unwrap_or("AW01"),
    )?;
    out.set_item("version", PROTOCOL_VERSION)?;
    out.set_item("static_dict_size", STATIC_DICT.len())?;
    Ok(out)
}

/// Stateful deterministic Rust guard-gate policy engine exposed to Python.
#[pyclass(name = "PolicyEngine")]
struct PyPolicyEngine {
    inner: CorePolicyEngine,
}

#[pymethods]
impl PyPolicyEngine {
    /// Construct a PolicyEngine using the default 4-role multi-agent policy, or parse `policy_json`.
    #[new]
    #[pyo3(signature = (policy_json=None))]
    fn new(policy_json: Option<&str>) -> PyResult<Self> {
        let inner = match policy_json {
            Some(json) => CorePolicyEngine::from_json(json)
                .map_err(|e| PyValueError::new_err(e.to_string()))?,
            None => CorePolicyEngine::default_multi_agent(),
        };
        Ok(Self { inner })
    }

    #[staticmethod]
    fn default_multi_agent() -> Self {
        Self {
            inner: CorePolicyEngine::default_multi_agent(),
        }
    }

    #[staticmethod]
    fn from_json(policy_json: &str) -> PyResult<Self> {
        let inner = CorePolicyEngine::from_json(policy_json)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Serialize the active policy specification to JSON.
    fn to_json(&self) -> PyResult<String> {
        self.inner
            .spec()
            .to_json()
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Pure read-only validation of a binary wire frame (does not consume session budget).
    fn validate_frame<'py>(&self, py: Python<'py>, raw_bytes: &[u8]) -> PyResult<Bound<'py, PyDict>> {
        let frame =
            core_decode_frame(raw_bytes).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let res = self.inner.validate_frame(&frame);
        validation_result_to_py(py, &res)
    }

    /// Stateful guard-gate evaluation: checks invariants and commits budget/hop counters on allow.
    fn evaluate_and_record<'py>(
        &mut self,
        py: Python<'py>,
        raw_bytes: &[u8],
    ) -> PyResult<Bound<'py, PyDict>> {
        let frame =
            core_decode_frame(raw_bytes).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let res = self.inner.evaluate_and_record(&frame);
        validation_result_to_py(py, &res)
    }

    /// Return remaining session token and micro-USD budget.
    fn remaining_budget<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let out = PyDict::new(py);
        out.set_item("remaining_tokens", self.inner.remaining_tokens())?;
        out.set_item("remaining_micro_usd", self.inner.remaining_micro_usd())?;
        let (evaluated, rejected) = self.inner.stats();
        out.set_item("evaluated_frames", evaluated)?;
        out.set_item("rejected_frames", rejected)?;
        Ok(out)
    }

    /// Reset session budget & cycle counters.
    fn reset(&mut self) {
        self.inner.reset_session();
    }
}

#[pymodule]
fn _agentwire(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encode_ast, m)?)?;
    m.add_function(wrap_pyfunction!(decode_frame, m)?)?;
    m.add_function(wrap_pyfunction!(validate_frame, m)?)?;
    m.add_function(wrap_pyfunction!(decompile_frame, m)?)?;
    m.add_function(wrap_pyfunction!(decompile_ast_dict, m)?)?;
    m.add_function(wrap_pyfunction!(protocol_info, m)?)?;
    m.add_class::<PyPolicyEngine>()?;
    Ok(())
}
