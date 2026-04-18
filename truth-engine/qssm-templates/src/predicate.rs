use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Comparison operator for [`PredicateBlock::Compare`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CmpOp {
    Gt,
    Lt,
    Eq,
}

/// One predicate in a verification template.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum PredicateBlock {
    Compare {
        field: String,
        op: CmpOp,
        rhs: Value,
    },
    Range { field: String, min: i64, max: i64 },
    InSet { field: String, values: Vec<i64> },
    AtLeast { field: String, min: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PredicateError {
    #[error("missing field: {0}")]
    MissingField(String),
    #[error("field is not a number: {0}")]
    NotANumber(String),
    #[error("invalid compare types")]
    CompareType,
    #[error("value out of range")]
    OutOfRange,
    #[error("value not in set")]
    NotInSet,
    #[error("predicate compare returned false")]
    CompareFalse,
    #[error("value below minimum")]
    BelowMin,
}

#[must_use]
pub fn json_at_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = root;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

fn as_i64_at(claim: &Value, field: &str) -> Result<i64, PredicateError> {
    let value = json_at_path(claim, field)
        .ok_or_else(|| PredicateError::MissingField(field.to_string()))?;
    value
        .as_i64()
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
                (Value::Number(a), Value::String(b)) => {
                    let ai = a.as_i64().ok_or(PredicateError::CompareType)?;
                    let bi: i64 = b.parse().map_err(|_| PredicateError::CompareType)?;
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
            let got = as_i64_at(claim, field)?;
            if (*min..=*max).contains(&got) {
                Ok(())
            } else {
                Err(PredicateError::OutOfRange)
            }
        }
        PredicateBlock::InSet { field, values } => {
            let got = as_i64_at(claim, field)?;
            if values.contains(&got) {
                Ok(())
            } else {
                Err(PredicateError::NotInSet)
            }
        }
        PredicateBlock::AtLeast { field, min } => {
            let got = as_i64_at(claim, field)?;
            if got >= *min {
                Ok(())
            } else {
                Err(PredicateError::BelowMin)
            }
        }
    }
}

#[must_use]
pub fn eval_all_predicates(claim: &Value, preds: &[PredicateBlock]) -> Result<(), PredicateError> {
    for pred in preds {
        eval_predicate(claim, pred)?;
    }
    Ok(())
}

pub fn predicate_blocks_from_template_value(v: &Value) -> Result<Vec<PredicateBlock>, String> {
    let arr = if let Some(array) = v.as_array() {
        array
    } else if let Some(array) = v.get("predicates").and_then(Value::as_array) {
        array
    } else {
        return Err("template must be an array or contain a predicates array".into());
    };
    let mut out = Vec::with_capacity(arr.len());
    for (index, item) in arr.iter().enumerate() {
        let block: PredicateBlock = serde_json::from_value(item.clone())
            .map_err(|error| format!("predicate[{index}] parse error: {error}"))?;
        out.push(block);
    }
    Ok(out)
}

#[must_use]
pub(crate) fn proof_of_age_predicates() -> Vec<PredicateBlock> {
    vec![PredicateBlock::Range {
        field: "claim.age_years".into(),
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
        let claim = json!({ "claim": { "age_years": 25 } });
        let predicate = PredicateBlock::Range {
            field: "claim.age_years".into(),
            min: 21,
            max: 150,
        };
        assert!(eval_predicate(&claim, &predicate).is_ok());
    }

    #[test]
    fn compare_gt() {
        let claim = json!({ "claim": { "score": 10 } });
        let predicate = PredicateBlock::Compare {
            field: "claim.score".into(),
            op: CmpOp::Gt,
            rhs: json!(5),
        };
        assert!(eval_predicate(&claim, &predicate).is_ok());
    }

    #[test]
    fn in_set() {
        let claim = json!({ "claim": { "bucket": 2 } });
        let predicate = PredicateBlock::InSet {
            field: "claim.bucket".into(),
            values: vec![1, 2, 3],
        };
        assert!(eval_predicate(&claim, &predicate).is_ok());
    }

    #[test]
    fn at_least_rejects_small_value() {
        let claim = json!({ "claim": { "account_age_years": 1 } });
        let predicate = PredicateBlock::AtLeast {
            field: "claim.account_age_years".into(),
            min: 2,
        };
        assert!(matches!(
            eval_predicate(&claim, &predicate),
            Err(PredicateError::BelowMin)
        ));
    }
}