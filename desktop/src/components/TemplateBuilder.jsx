import { useEffect, useState } from "react";

const EMPTY_PREDICATE = {
  kind: "range",
  field: "claim.",
  min: 0,
  max: 150,
  op: "gt",
  rhs: "",
  values: "",
};

const ANCHOR_KINDS = ["anchor_hash", "static_root", "timestamp_unix_secs"];

function newPredicate() {
  return { ...EMPTY_PREDICATE, _key: crypto.randomUUID() };
}

function createDefaultState() {
  return {
    id: "custom-template",
    title: "Custom template",
    description: "",
    anchors: ["anchor_hash"],
    predicates: [newPredicate()],
  };
}

function createProofOfAgeState() {
  return {
    id: "age-gate-21",
    title: "Proof of age (21+)",
    description: "Public claim must include claim.age_years between 21 and 150 inclusive.",
    anchors: ["anchor_hash", "static_root", "timestamp_unix_secs"],
    predicates: [
      {
        _key: crypto.randomUUID(),
        kind: "range",
        field: "claim.age_years",
        min: 21,
        max: 150,
        op: "gt",
        rhs: "",
        values: "",
      },
    ],
  };
}

export default function TemplateBuilder({ onGenerate, onResetAll, resetToken }) {
  const [builderState, setBuilderState] = useState(createDefaultState);

  const { id, title, description, anchors, predicates } = builderState;

  useEffect(() => {
    setBuilderState(createDefaultState());
  }, [resetToken]);

  function updateBuilder(patch) {
    setBuilderState((prev) => ({ ...prev, ...patch }));
  }

  function toggleAnchor(kind) {
    updateBuilder({
      anchors: anchors.includes(kind)
        ? anchors.filter((a) => a !== kind)
        : [...anchors, kind],
    });
  }

  function updatePred(index, patch) {
    updateBuilder({
      predicates: predicates.map((p, i) => (i === index ? { ...p, ...patch } : p)),
    });
  }

  function removePred(index) {
    updateBuilder({ predicates: predicates.filter((_, i) => i !== index) });
  }

  function addPred() {
    updateBuilder({ predicates: [...predicates, newPredicate()] });
  }

  function resetBuilder() {
    setBuilderState(createDefaultState());
  }

  function loadProofOfAgeExample() {
    const next = createProofOfAgeState();
    setBuilderState(next);
    const template = toTemplate(next);
    if (onGenerate) {
      onGenerate(
        JSON.stringify(template, null, 2),
        buildExampleClaim(template.predicates),
      );
    }
  }

  function generate() {
    const template = toTemplate(builderState);

    const json = JSON.stringify(template, null, 2);

    // Build an example claim that satisfies all predicates
    const exampleClaim = buildExampleClaim(template.predicates);

    if (onGenerate) onGenerate(json, exampleClaim);
  }

  return (
    <div className="panel">
      <h2>Template builder</h2>
      <p className="muted">
        Chain predicates into a custom template. All predicates must pass (AND logic).
        Click <strong>Generate JSON</strong> to populate the template editor above.
      </p>

      <div style={{ marginTop: "0.75rem", display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        <button type="button" className="btn" onClick={loadProofOfAgeExample}>
          Load proof of age example
        </button>
        <button type="button" className="btn btn-ghost" onClick={resetBuilder}>
          Clear builder
        </button>
        <button type="button" className="btn btn-ghost" onClick={onResetAll}>
          Clear app
        </button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", marginTop: "0.75rem" }}>
        <label className="muted">
          Template id
          <input value={id} onChange={(e) => updateBuilder({ id: e.target.value })} placeholder="custom-template" />
        </label>
        <label className="muted">
          Title
          <input value={title} onChange={(e) => updateBuilder({ title: e.target.value })} placeholder="Custom template" />
        </label>
      </div>

      <label className="muted" style={{ display: "block", marginTop: "0.5rem" }}>
        Description (optional)
        <input value={description} onChange={(e) => updateBuilder({ description: e.target.value })} placeholder="What this template checks" />
      </label>

      <fieldset style={{ marginTop: "0.75rem", border: "1px solid var(--accent)", padding: "0.5rem 0.75rem", borderRadius: "6px" }}>
        <legend className="muted" style={{ padding: "0 0.35rem" }}>Allowed anchor kinds</legend>
        <div style={{ display: "flex", gap: "1rem", flexWrap: "wrap" }}>
          {ANCHOR_KINDS.map((kind) => (
            <label key={kind} style={{ display: "flex", gap: "0.35rem", alignItems: "center", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={anchors.includes(kind)}
                onChange={() => toggleAnchor(kind)}
              />
              <span className="muted">{kind}</span>
            </label>
          ))}
        </div>
      </fieldset>

      <div style={{ marginTop: "0.75rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <strong className="muted">Predicates</strong>
          <button type="button" className="btn btn-ghost" onClick={addPred} style={{ padding: "0.2rem 0.6rem", fontSize: "0.8rem" }}>
            + Add predicate
          </button>
        </div>

        {predicates.map((pred, i) => (
          <div
            key={pred._key}
            style={{
              marginTop: "0.5rem",
              padding: "0.6rem",
              border: "1px solid var(--border, #ddd)",
              borderRadius: "6px",
              display: "flex",
              flexWrap: "wrap",
              gap: "0.5rem",
              alignItems: "end",
            }}
          >
            <label className="muted" style={{ minWidth: "8rem" }}>
              Kind
              <select value={pred.kind} onChange={(e) => updatePred(i, { kind: e.target.value })}>
                <option value="range">Range</option>
                <option value="at_least">At least</option>
                <option value="compare">Compare</option>
                <option value="in_set">In set</option>
              </select>
            </label>

            <label className="muted" style={{ flex: "1 1 10rem" }}>
              Field (dot path)
              <input value={pred.field} onChange={(e) => updatePred(i, { field: e.target.value })} placeholder="claim.age_years" />
            </label>

            {(pred.kind === "range" || pred.kind === "at_least") && (
              <label className="muted" style={{ width: "5rem" }}>
                Min
                <input type="number" value={pred.min} onChange={(e) => updatePred(i, { min: e.target.value })} />
              </label>
            )}

            {pred.kind === "range" && (
              <label className="muted" style={{ width: "5rem" }}>
                Max
                <input type="number" value={pred.max} onChange={(e) => updatePred(i, { max: e.target.value })} />
              </label>
            )}

            {pred.kind === "compare" && (
              <>
                <label className="muted" style={{ width: "5rem" }}>
                  Op
                  <select value={pred.op} onChange={(e) => updatePred(i, { op: e.target.value })}>
                    <option value="gt">gt (&gt;)</option>
                    <option value="lt">lt (&lt;)</option>
                    <option value="eq">eq (=)</option>
                  </select>
                </label>
                <label className="muted" style={{ width: "6rem" }}>
                  RHS
                  <input value={pred.rhs} onChange={(e) => updatePred(i, { rhs: e.target.value })} placeholder="42" />
                </label>
              </>
            )}

            {pred.kind === "in_set" && (
              <label className="muted" style={{ flex: "1 1 10rem" }}>
                Values (comma separated)
                <input value={pred.values} onChange={(e) => updatePred(i, { values: e.target.value })} placeholder="1,2,3" />
              </label>
            )}

            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => removePred(i)}
              disabled={predicates.length <= 1}
              style={{ padding: "0.2rem 0.5rem", fontSize: "0.8rem" }}
              title="Remove predicate"
            >
              ✕
            </button>
          </div>
        ))}
      </div>

      <div style={{ marginTop: "0.75rem", display: "flex", gap: "0.5rem" }}>
        <button type="button" className="btn" onClick={generate}>
          Generate template JSON
        </button>
      </div>
    </div>
  );
}

function parseRhs(raw) {
  const trimmed = String(raw).trim();
  const asNum = Number(trimmed);
  return Number.isNaN(asNum) ? trimmed : asNum;
}

function toTemplate({ id, title, description, anchors, predicates }) {
  return {
    qssm_template_version: 1,
    id: id.trim() || "custom-template",
    title: title.trim() || "Custom template",
    ...(description.trim() ? { description: description.trim() } : {}),
    allowed_anchor_kinds: anchors.length > 0 ? anchors : ["anchor_hash"],
    predicates: predicates.map(({ kind, field, min, max, op, rhs, values }) => {
      const f = field.trim() || "claim.value";
      switch (kind) {
        case "range":
          return { kind: "range", field: f, min: Number(min) || 0, max: Number(max) || 150 };
        case "at_least":
          return { kind: "at_least", field: f, min: Number(min) || 0 };
        case "compare":
          return { kind: "compare", field: f, op, rhs: parseRhs(rhs) };
        case "in_set":
          return {
            kind: "in_set",
            field: f,
            values: String(values)
              .split(",")
              .map((v) => Number(v.trim()))
              .filter((v) => !Number.isNaN(v)),
          };
        default:
          return { kind: "range", field: f, min: 0, max: 150 };
      }
    }),
  };
}

/**
 * Build a sample claim JSON object from predicates so the user has a
 * ready-to-use starting point. Each predicate contributes a value at its
 * dot-path that would satisfy the rule.
 */
function buildExampleClaim(predicates) {
  const claim = {};
  for (const pred of predicates) {
    const path = pred.field || "claim.value";
    let value;
    switch (pred.kind) {
      case "range":
        value = pred.min ?? 0;
        break;
      case "at_least":
        value = pred.min ?? 0;
        break;
      case "compare":
        if (pred.op === "gt") value = (Number(pred.rhs) || 0) + 1;
        else if (pred.op === "lt") value = (Number(pred.rhs) || 0) - 1;
        else value = typeof pred.rhs === "number" ? pred.rhs : pred.rhs;
        break;
      case "in_set":
        value = Array.isArray(pred.values) && pred.values.length > 0 ? pred.values[0] : 0;
        break;
      default:
        value = 0;
    }
    setNestedPath(claim, path, value);
  }
  return JSON.stringify(claim, null, 2);
}

/** Set a value at a dot-separated path inside an object, creating parents as needed. */
function setNestedPath(obj, dotPath, value) {
  const parts = dotPath.split(".");
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    if (!(key in cur) || typeof cur[key] !== "object") cur[key] = {};
    cur = cur[key];
  }
  cur[parts[parts.length - 1]] = value;
}
