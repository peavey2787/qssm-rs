// Copyright (c) 2026 Peavey Koding. All rights reserved.
// Licensed under the Business Source License 1.1 (BSL-1.1).
// See the LICENSE file in the repository root for full license text.

//! Declarative **predicate blocks** for generic verification templates (comparison, range, set membership).
//!
//! Values are read from a public **`serde_json::Value`** (object tree) using dot paths, e.g. **`claim.age_years`**.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Comparison operator for [`PredicateBlock::Compare`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CmpOp {
    Gt,
    Lt,
    Eq,
}

/// One predicate in a verification template.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PredicateBlock {
    /// Numeric or string compare: **`lhs op rhs`** where **`lhs`** is **`field`** in the claim JSON.
    Compare {
        field: String,
        op: CmpOp,
        /// JSON number or string (rhs is not taken from the claim).
        rhs: Value,
    },
    /// Inclusive numeric range **`min <= field <= max`**.
    Range { field: String, min: i64, max: i64 },
    /// Numeric membership: field must equal one of **`values`**.
    InSet { field: String, values: Vec<i64> },
    /// Inclusive numeric floor **`field >= min`** (“at least” / min‑threshold proofs).
    AtLeast { field: String, min: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredicateError {
    MissingField(String),
    NotANumber(String),
    CompareType,
    OutOfRange,
    NotInSet,
    CompareFalse,
    BelowMin,
}

impl std::fmt::Display for PredicateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField(p) => write!(f, "missing or non-object path: {p}"),
            Self::NotANumber(p) => write!(f, "expected number at {p}"),
            Self::CompareType => write!(f, "compare: type mismatch"),
            Self::OutOfRange => write!(f, "range: value outside [min,max]"),
            Self::NotInSet => write!(f, "set: value not in allowed set"),
            Self::CompareFalse => write!(f, "compare: relation is false"),
            Self::BelowMin => write!(f, "at_least: value below minimum"),
        }
    }
}

impl std::error::Error for PredicateError {}

#[must_use]
pub fn json_at_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = root;
    for seg in path.split('.') {
        if seg.is_empty() {
            continue;
        }
        cur = cur.get(seg)?;
    }
    Some(cur)
}

fn as_i64_at(claim: &Value, field: &str) -> Result<i64, PredicateError> {
    let v = json_at_path(claim, field)
        .ok_or_else(|| PredicateError::MissingField(field.to_string()))?;
    v.as_i64()
        .ok_or_else(|| PredicateError::NotANumber(field.to_string()))
}

#[must_use]
pub fn eval_predicate(claim: &Value, pred: &PredicateBlock) -> Result<(), PredicateError> {
    match pred {
        PredicateBlock::Compare { field, op, rhs } => {
            let lhs = json_at_path(claim, field)
                .ok_or_else(|| PredicateError::MissingField(field.clone()))?;
            let ok = match (lhs, rhs) {
                (Value::Number(a), Value::Number(b)) => {
                    let ai = a.as_i64().ok_or(PredicateError::CompareType)?;
                    let bi = b.as_i64().ok_or(PredicateError::CompareType)?;
                    match op {
                        CmpOp::Gt => ai > bi,
                        CmpOp::Lt => ai < bi,
                        CmpOp::Eq => ai == bi,
                    }
                }
                (Value::String(a), Value::String(b)) => match op {
                    CmpOp::Eq => a == b,
                    CmpOp::Gt | CmpOp::Lt => return Err(PredicateError::CompareType),
                },
                (Value::Number(a), Value::String(bs)) => {
                    let ai = a.as_i64().ok_or(PredicateError::CompareType)?;
                    let bi: i64 = bs.parse().map_err(|_| PredicateError::CompareType)?;
                    match op {
                        CmpOp::Gt => ai > bi,
                        CmpOp::Lt => ai < bi,
                        CmpOp::Eq => ai == bi,
                    }
                }
                _ => return Err(PredicateError::CompareType),
            };
            if ok {
                Ok(())
            } else {
                Err(PredicateError::CompareFalse)
            }
        }
        PredicateBlock::Range { field, min, max } => {
            let n = as_i64_at(claim, field)?;
            if n >= *min && n <= *max {
                Ok(())
            } else {
                Err(PredicateError::OutOfRange)
            }
        }
        PredicateBlock::InSet { field, values } => {
            let n = as_i64_at(claim, field)?;
            if values.iter().any(|v| *v == n) {
                Ok(())
            } else {
                Err(PredicateError::NotInSet)
            }
        }
        PredicateBlock::AtLeast { field, min } => {
            let n = as_i64_at(claim, field)?;
            if n >= *min {
                Ok(())
            } else {
                Err(PredicateError::BelowMin)
            }
        }
    }
}

/// **`Ok(())`** iff every predicate passes.
#[must_use]
pub fn eval_all_predicates(claim: &Value, preds: &[PredicateBlock]) -> Result<(), PredicateError> {
    for p in preds {
        eval_predicate(claim, p)?;
    }
    Ok(())
}

/// Parse a template JSON value into predicate blocks.
///
/// Accepts either a bare JSON array of [`PredicateBlock`] objects, or an object with a **`predicates`** array
/// (optional **`template_id`** is ignored here; use [`crate::predicate_templates::standard_library_script`] for ids).
pub fn predicate_blocks_from_template_value(v: &Value) -> Result<Vec<PredicateBlock>, String> {
    let arr = if let Some(a) = v.as_array() {
        a
    } else if let Some(a) = v.get("predicates").and_then(Value::as_array) {
        a
    } else {
        return Err(
            "template_script: expected top-level JSON array or object with \"predicates\" array"
                .into(),
        );
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let b: PredicateBlock = serde_json::from_value(item.clone())
            .map_err(|e| format!("predicates[{i}]: {e}"))?;
        out.push(b);
    }
    Ok(out)
}

/// Proof‑of‑age style template: **`claim.age_years` ∈ [21, 150]** (inclusive).
#[must_use]
pub fn proof_of_age_predicates() -> Vec<PredicateBlock> {
    vec![PredicateBlock::Range {
        field: "claim.age_years".to_string(),
        min: 21,
        max: 150,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn range_ok() {
        let claim = json!({ "claim": { "age_years": 30 } });
        let p = PredicateBlock::Range {
            field: "claim.age_years".into(),
            min: 21,
            max: 150,
        };
        assert!(eval_predicate(&claim, &p).is_ok());
    }

    #[test]
    fn compare_gt() {
        let claim = json!({ "x": { "n": 10 } });
        let p = PredicateBlock::Compare {
            field: "x.n".into(),
            op: CmpOp::Gt,
            rhs: json!(3),
        };
        assert!(eval_predicate(&claim, &p).is_ok());
    }

    #[test]
    fn in_set() {
        let claim = json!({ "tier": 2 });
        let p = PredicateBlock::InSet {
            field: "tier".into(),
            values: vec![1, 2, 3],
        };
        assert!(eval_predicate(&claim, &p).is_ok());
    }

    #[test]
    fn at_least_ok_and_fail() {
        let claim = json!({ "claim": { "account_age_years": 30 } });
        let p = PredicateBlock::AtLeast {
            field: "claim.account_age_years".into(),
            min: 21,
        };
        assert!(eval_predicate(&claim, &p).is_ok());
        let young = json!({ "claim": { "account_age_years": 12 } });
        assert!(eval_predicate(&young, &p).is_err());
    }

    #[test]
    fn predicate_blocks_from_template_object() {
        let v = json!({
            "template_id": "t",
            "predicates": [
                { "kind": "range", "field": "n", "min": 0, "max": 5 }
            ]
        });
        let blocks = predicate_blocks_from_template_value(&v).unwrap();
        assert_eq!(blocks.len(), 1);
        let claim = json!({ "n": 3 });
        assert!(eval_all_predicates(&claim, &blocks).is_ok());
    }
}
