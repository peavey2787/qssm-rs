import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";

const DEFAULT_HEX32 = `${"00".repeat(31)}01`;
const DEFAULT_CLAIM_JSON = '{"claim":{"age_years":22}}';

const TRUTH_GATE_PRESETS = {
  blank: { kind: "compare", field: "", op: "gt", rhs: "0" },
  greater_than: { kind: "compare", field: "claim.value", op: "gt", rhs: "0" },
  less_than: { kind: "compare", field: "claim.value", op: "lt", rhs: "100" },
  age_21: { kind: "range", field: "claim.age_years", min: "21", max: "150" },
};

export default function AdvancedLaboratory() {
  const inTauri = typeof window !== "undefined" && !!window.__TAURI_INTERNALS__?.invoke;
  const [handoffJson, setHandoffJson] = useState("");
  const [dropDrag, setDropDrag] = useState(false);
  const [out, setOut] = useState("(no run yet)");
  const [busy, setBusy] = useState(false);
  const [hud, setHud] = useState({
    l1_sync: "Connected to Kaspa Node (mock)",
    entropy_anchor_kind: "—",
    qrng_status: "—",
    prover_latency_ms: null,
  });
  const [anchorMode, setAnchorMode] = useState("kaspa");
  const [anchorHex, setAnchorHex] = useState(DEFAULT_HEX32);
  const [anchorTs, setAnchorTs] = useState("1700000000");
  const [stateRootHex, setStateRootHex] = useState(DEFAULT_HEX32);
  const [rollupDigestHex, setRollupDigestHex] = useState(DEFAULT_HEX32);
  const [n, setN] = useState("1");
  const [k, setK] = useState("0");
  const [bitAtK, setBitAtK] = useState("0");
  const [challengeHex, setChallengeHex] = useState(DEFAULT_HEX32);
  const [localEntropyHex, setLocalEntropyHex] = useState("");
  const [predicates, setPredicates] = useState([]);
  const [presetPick, setPresetPick] = useState("");
  const [templateId, setTemplateId] = useState("my-claim");
  const [templateTitle, setTemplateTitle] = useState("Custom claim");
  const [exportPath, setExportPath] = useState("");
  const [templateJson, setTemplateJson] = useState("");
  const [claimJson, setClaimJson] = useState(DEFAULT_CLAIM_JSON);
  const [verifyOut, setVerifyOut] = useState("(no verify yet)");

  const proverLatency = useMemo(() => {
    if (typeof hud.prover_latency_ms !== "number") return "—";
    return `${hud.prover_latency_ms.toFixed(2)} ms`;
  }, [hud.prover_latency_ms]);

  useEffect(() => {
    if (!inTauri) return () => {};
    let unlisten;
    (async () => {
      try {
        const win = getCurrentWindow();
        unlisten = await win.onDragDropEvent(async (event) => {
          if (event.payload.type !== "drop") return;
          const path = event.payload.paths?.[0];
          if (!path) return;
          setBusy(true);
          setOut("Running…");
          try {
            const res = await invoke("generate_proof_from_file", { path });
            applyResult(res);
          } catch (e) {
            showErr(e);
          } finally {
            setBusy(false);
          }
        });
      } catch {
        // noop for browser mode.
      }
    })();
    return () => {
      if (typeof unlisten === "function") unlisten();
    };
  }, [inTauri]);

  function applyResult(res) {
    const parsed = typeof res === "string" ? JSON.parse(res) : res;
    setHud({
      l1_sync: parsed.l1_sync ?? "—",
      entropy_anchor_kind: parsed.entropy_anchor_kind ?? "—",
      qrng_status:
        parsed.qrng_status === "nist" || parsed.nist_included === true
          ? "NIST pulse active"
          : parsed.qrng_status === "fallback" || parsed.nist_included === false
            ? "Fallback mode (anchor || local floor)"
            : parsed.qrng_status ?? "—",
      prover_latency_ms: parsed.prover_latency_ms,
    });
    setOut(JSON.stringify(parsed, null, 2));
  }

  function showErr(err) {
    setOut(String(err));
    setHud((prev) => ({
      ...prev,
      entropy_anchor_kind: "—",
      qrng_status: "—",
      prover_latency_ms: null,
    }));
  }

  function buildAnchorFromForm() {
    if (anchorMode === "timestamp") {
      const unix = Number.parseInt(anchorTs, 10);
      if (!Number.isFinite(unix) || unix < 0) throw new Error("Invalid Unix seconds");
      return { kind: "timestamp", unix_secs: unix };
    }
    if (anchorMode === "static_root") return { kind: "static_root", root_hex: anchorHex.trim() };
    return { kind: "kaspa", parent_block_id_hex: anchorHex.trim() };
  }

  function buildHandoffFromForm() {
    const o = {
      anchor: buildAnchorFromForm(),
      state_root_hex: stateRootHex.trim(),
      rollup_context_digest_hex: rollupDigestHex.trim(),
      n: Number.parseInt(n, 10),
      k: Number.parseInt(k, 10),
      bit_at_k: Number.parseInt(bitAtK, 10),
      challenge_hex: challengeHex.trim(),
    };
    const local = localEntropyHex.trim();
    if (local) o.local_entropy_hex = local;
    return JSON.stringify(o);
  }

  function addPredicateRow(preset) {
    const p = preset ?? TRUTH_GATE_PRESETS.blank;
    setPredicates((prev) => [
      ...prev,
      {
        kind: p.kind,
        field: p.field ?? "",
        min: p.min ?? "21",
        max: p.max ?? "150",
        op: p.op ?? "gt",
        rhs: p.rhs ?? "0",
        values: p.values ?? "1,2,3",
      },
    ]);
  }

  function collectPredicates() {
    return predicates.map((p) => {
      const field = String(p.field ?? "").trim();
      if (!field) throw new Error("Every Truth Gate needs a non-empty field (dot path).");
      if (p.kind === "range") {
        const min = Number.parseInt(p.min, 10);
        const max = Number.parseInt(p.max, 10);
        if (!Number.isFinite(min) || !Number.isFinite(max)) throw new Error(`Invalid range for field ${field}`);
        return { kind: "range", field, min, max };
      }
      if (p.kind === "compare") {
        const rhsRaw = String(p.rhs ?? "").trim();
        let rhs;
        try {
          rhs = JSON.parse(rhsRaw);
        } catch {
          rhs = Number.parseInt(rhsRaw, 10);
          if (!Number.isFinite(rhs)) throw new Error(`Invalid rhs JSON for ${field}`);
        }
        return { kind: "compare", field, op: p.op || "gt", rhs };
      }
      const values = String(p.values ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
        .map((s) => Number.parseInt(s, 10));
      if (values.some((v) => !Number.isFinite(v))) throw new Error(`Invalid in_set values for ${field}`);
      return { kind: "in_set", field, values };
    });
  }

  async function runHandoff() {
    if (!inTauri) {
      setOut("Rust command bridge unavailable. Launch via `cargo tauri dev`.");
      return;
    }
    setBusy(true);
    try {
      const res = await invoke("generate_proof_from_handoff_json", { json: handoffJson });
      applyResult(res);
    } catch (e) {
      showErr(e);
    } finally {
      setBusy(false);
    }
  }

  async function loadPoaTemplate() {
    if (!inTauri) {
      setVerifyOut("Rust command bridge unavailable. Launch via `cargo tauri dev`.");
      return;
    }
    try {
      const s = await invoke("proof_of_age_template_json");
      setTemplateJson(s);
      setVerifyOut("Loaded proof-of-age template.");
    } catch (e) {
      setVerifyOut(String(e));
    }
  }

  async function verifyClaim() {
    if (!inTauri) {
      setVerifyOut("Rust command bridge unavailable. Launch via `cargo tauri dev`.");
      return;
    }
    try {
      const res = await invoke("verify_claim_with_template", {
        templateJson,
        claimJson,
      });
      setVerifyOut(typeof res === "string" ? res : JSON.stringify(res, null, 2));
    } catch (e) {
      setVerifyOut(String(e));
    }
  }

  async function runGenericPipeline() {
    if (!inTauri) {
      setOut("Rust command bridge unavailable. Launch via `cargo tauri dev`.");
      return;
    }
    setBusy(true);
    setOut("Running…");
    try {
      const json = buildHandoffFromForm();
      const res = await invoke("generate_proof_from_handoff_json", { json });
      applyResult(res);
    } catch (e) {
      showErr(e);
    } finally {
      setBusy(false);
    }
  }

  async function exportQssmTemplate() {
    if (!exportPath.trim()) {
      setVerifyOut("Set export path first.");
      return;
    }
    if (!inTauri) {
      setVerifyOut("Rust command bridge unavailable. Launch via `cargo tauri dev`.");
      return;
    }
    try {
      const vk = await invoke("lattice_demo_vk_seed_hex");
      const tpl = {
        qssm_template_version: 1,
        id: templateId.trim() || "template",
        title: templateTitle.trim() || "Template",
        allowed_anchor_kinds: ["kaspa_parent_block", "static_root", "timestamp_unix_secs"],
        predicates: collectPredicates(),
        lattice_vk_seed_hex: vk,
        notes: "Exported from QSSM Desktop - Truth Gates / digital laws (PredicateBlock schema).",
      };
      await invoke("export_qssm_template", {
        path: exportPath.trim(),
        templateJson: JSON.stringify(tpl),
      });
      setVerifyOut(`Wrote ${exportPath}\n\n${JSON.stringify(tpl, null, 2)}`);
    } catch (e) {
      setVerifyOut(String(e));
    }
  }

  return (
    <div className="lab-wrap">
      <h2 style={{ marginTop: 0 }}>Lab</h2>
      <div className="panel">
        <div className="muted" style={{ marginBottom: "0.5rem" }}>
          <strong>L1 / anchor status:</strong> {hud.l1_sync}
        </div>
        <div className="muted" style={{ marginBottom: "0.5rem" }}>
          <strong>Entropy anchor kind:</strong> {hud.entropy_anchor_kind}
        </div>
        <div className="muted" style={{ marginBottom: "0.5rem" }}>
          <strong>QRNG / NIST:</strong> {hud.qrng_status}
        </div>
        <div className="muted">
          <strong>Prover latency (30-bit limb):</strong> {proverLatency}
        </div>
      </div>

      <div className="panel">
        <h2>Rollup handoff (JSON file)</h2>
        <div
          style={{
            border: "2px dashed var(--accent)",
            borderRadius: "8px",
            padding: "1rem",
            background: dropDrag ? "rgba(61,157,255,0.12)" : "#0d1117",
          }}
          onDragEnter={(e) => {
            e.preventDefault();
            setDropDrag(true);
          }}
          onDragOver={(e) => {
            e.preventDefault();
            setDropDrag(true);
          }}
          onDragLeave={() => setDropDrag(false)}
          onDrop={async (e) => {
            e.preventDefault();
            setDropDrag(false);
            const f = e.dataTransfer?.files?.[0];
            if (!f) return;
            setBusy(true);
            setOut("Running…");
            try {
              const text = await f.text();
              const res = await invoke("generate_proof_from_handoff_json", { json: text });
              applyResult(res);
            } catch (err) {
              showErr(err);
            } finally {
              setBusy(false);
            }
          }}
        >
          <p>
            <strong>Drop a handoff JSON file</strong> or use file input.
          </p>
          <label className="muted" style={{ display: "flex", flexDirection: "column", gap: "0.35rem" }}>
            JSON file
            <input
              type="file"
              accept=".json,application/json"
              onChange={async (e) => {
                const f = e.target.files?.[0];
                if (!f) return;
                setBusy(true);
                setOut("Running…");
                try {
                  const text = await f.text();
                  const res = await invoke("generate_proof_from_handoff_json", { json: text });
                  applyResult(res);
                } catch (err) {
                  showErr(err);
                } finally {
                  setBusy(false);
                }
              }}
            />
          </label>
        </div>
      </div>

      <div className="panel">
        <h2>Generic verification mode</h2>
        <p className="muted">
          Build a handoff without Kaspa and compose Truth Gates (digital laws) for `.qssm` export.
        </p>
        <div style={{ display: "flex", gap: "0.8rem", flexWrap: "wrap", marginBottom: "0.75rem" }}>
          <label className="muted"><input type="radio" checked={anchorMode === "kaspa"} onChange={() => setAnchorMode("kaspa")} /> Kaspa parent</label>
          <label className="muted"><input type="radio" checked={anchorMode === "static_root"} onChange={() => setAnchorMode("static_root")} /> Static root</label>
          <label className="muted"><input type="radio" checked={anchorMode === "timestamp"} onChange={() => setAnchorMode("timestamp")} /> Timestamp</label>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
          <label className="muted">Kaspa parent / static root hex (32 bytes)<input value={anchorHex} onChange={(e) => setAnchorHex(e.target.value)} /></label>
          <label className="muted">Unix seconds<input type="number" value={anchorTs} onChange={(e) => setAnchorTs(e.target.value)} /></label>
          <label className="muted">state_root_hex<input value={stateRootHex} onChange={(e) => setStateRootHex(e.target.value)} /></label>
          <label className="muted">rollup_context_digest_hex<input value={rollupDigestHex} onChange={(e) => setRollupDigestHex(e.target.value)} /></label>
          <label className="muted">n<input type="number" min="0" max="255" value={n} onChange={(e) => setN(e.target.value)} /></label>
          <label className="muted">k<input type="number" min="0" max="255" value={k} onChange={(e) => setK(e.target.value)} /></label>
          <label className="muted">bit_at_k<input type="number" min="0" max="1" value={bitAtK} onChange={(e) => setBitAtK(e.target.value)} /></label>
          <label className="muted">challenge_hex<input value={challengeHex} onChange={(e) => setChallengeHex(e.target.value)} /></label>
          <label className="muted">local_entropy_hex (optional)<input value={localEntropyHex} onChange={(e) => setLocalEntropyHex(e.target.value)} /></label>
        </div>
        <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", alignItems: "end", marginTop: "0.75rem" }}>
          <label className="muted">
            Preset
            <select value={presetPick} onChange={(e) => setPresetPick(e.target.value)} style={{ marginLeft: "0.4rem" }}>
              <option value="">Choose preset…</option>
              <option value="blank">Blank gate</option>
              <option value="greater_than">Greater than (&gt;)</option>
              <option value="less_than">Less than (&lt;)</option>
              <option value="age_21">Age check (21+)</option>
            </select>
          </label>
          <button type="button" className="btn btn-ghost" onClick={() => {
            if (!presetPick) return setVerifyOut("Choose a Truth Gate preset from the dropdown first.");
            addPredicateRow(TRUTH_GATE_PRESETS[presetPick]);
            setPresetPick("");
            setVerifyOut("");
          }}>Add Truth Gate</button>
          <button type="button" className="btn btn-ghost" onClick={() => addPredicateRow(TRUTH_GATE_PRESETS.greater_than)}>Greater Than</button>
          <button type="button" className="btn btn-ghost" onClick={() => addPredicateRow(TRUTH_GATE_PRESETS.less_than)}>Less Than</button>
          <button type="button" className="btn btn-ghost" onClick={() => addPredicateRow(TRUTH_GATE_PRESETS.age_21)}>Age Check (21+)</button>
        </div>

        <div style={{ marginTop: "0.75rem", display: "grid", gap: "0.5rem" }}>
          {predicates.map((p, idx) => (
            <div key={`pred-${idx}`} className="panel" style={{ margin: 0, padding: "0.6rem", background: "#0d1117" }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr auto", gap: "0.5rem" }}>
                <label className="muted">Gate kind
                  <select value={p.kind} onChange={(e) => setPredicates((prev) => prev.map((it, i) => i === idx ? { ...it, kind: e.target.value } : it))}>
                    <option value="range">Range (digital law band)</option>
                    <option value="compare">Compare (Truth Gate)</option>
                    <option value="in_set">In set</option>
                  </select>
                </label>
                <label className="muted">Field (dot path)<input value={p.field} onChange={(e) => setPredicates((prev) => prev.map((it, i) => i === idx ? { ...it, field: e.target.value } : it))} /></label>
                <button type="button" className="btn btn-ghost" onClick={() => setPredicates((prev) => prev.filter((_, i) => i !== idx))}>Remove</button>
              </div>
              {p.kind === "range" && (
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem", marginTop: "0.5rem" }}>
                  <label className="muted">min<input value={p.min} onChange={(e) => setPredicates((prev) => prev.map((it, i) => i === idx ? { ...it, min: e.target.value } : it))} /></label>
                  <label className="muted">max<input value={p.max} onChange={(e) => setPredicates((prev) => prev.map((it, i) => i === idx ? { ...it, max: e.target.value } : it))} /></label>
                </div>
              )}
              {p.kind === "compare" && (
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem", marginTop: "0.5rem" }}>
                  <label className="muted">Op
                    <select value={p.op} onChange={(e) => setPredicates((prev) => prev.map((it, i) => i === idx ? { ...it, op: e.target.value } : it))}>
                      <option value="gt">gt (&gt;)</option>
                      <option value="lt">lt (&lt;)</option>
                      <option value="eq">eq (==)</option>
                    </select>
                  </label>
                  <label className="muted">rhs (JSON number)<input value={p.rhs} onChange={(e) => setPredicates((prev) => prev.map((it, i) => i === idx ? { ...it, rhs: e.target.value } : it))} /></label>
                </div>
              )}
              {p.kind === "in_set" && <label className="muted" style={{ marginTop: "0.5rem", display: "block" }}>Values (comma-separated integers)<input value={p.values} onChange={(e) => setPredicates((prev) => prev.map((it, i) => i === idx ? { ...it, values: e.target.value } : it))} /></label>}
            </div>
          ))}
        </div>
        <button type="button" className="btn btn-ghost" style={{ marginTop: "0.5rem" }} onClick={() => addPredicateRow(TRUTH_GATE_PRESETS.blank)}>+ Add blank Truth Gate</button>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", marginTop: "0.75rem" }}>
          <label className="muted">Template id<input value={templateId} onChange={(e) => setTemplateId(e.target.value)} /></label>
          <label className="muted">Template title<input value={templateTitle} onChange={(e) => setTemplateTitle(e.target.value)} /></label>
        </div>
        <div style={{ marginTop: "0.5rem", display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <button type="button" className="btn" disabled={busy} onClick={runGenericPipeline}>
            Run pipeline from form
          </button>
          <button type="button" className="btn btn-ghost" onClick={() => {
            setPredicates([{
              kind: "range",
              field: "claim.age_years",
              min: "21",
              max: "150",
              op: "gt",
              rhs: "0",
              values: "1,2,3",
            }]);
            setTemplateId("proof-of-age-21");
            setTemplateTitle("Proof of age (21+) - Truth Gate");
          }}>
            Digital law preset: proof of age (21+)
          </button>
          <button type="button" className="btn btn-ghost" onClick={exportQssmTemplate}>
            Export .qssm template
          </button>
          <label className="muted" style={{ minWidth: "18rem", flex: 1 }}>
            Export path (absolute; desktop only)
            <input value={exportPath} onChange={(e) => setExportPath(e.target.value)} placeholder="C:\\path\\claim.qssm" />
          </label>
        </div>
      </div>

      <div className="panel">
        <h2>Truth Gates — verify claim vs .qssm</h2>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
          <label className="muted" style={{ display: "flex", flexDirection: "column", gap: "0.35rem" }}>
            Template JSON
            <textarea
              style={{ minHeight: "120px", fontFamily: "ui-monospace, monospace", fontSize: "0.78rem" }}
              value={templateJson}
              onChange={(e) => setTemplateJson(e.target.value)}
            />
          </label>
          <label className="muted" style={{ display: "flex", flexDirection: "column", gap: "0.35rem" }}>
            Public claim JSON
            <textarea
              style={{ minHeight: "120px", fontFamily: "ui-monospace, monospace", fontSize: "0.78rem" }}
              value={claimJson}
              onChange={(e) => setClaimJson(e.target.value)}
            />
          </label>
        </div>
        <div style={{ marginTop: "0.5rem", display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <button type="button" className="btn" onClick={verifyClaim}>
            Run Truth Gate check
          </button>
          <button type="button" className="btn btn-ghost" onClick={loadPoaTemplate}>
            Load proof-of-age template
          </button>
        </div>
        <pre className="pre-log" style={{ marginTop: "0.75rem" }}>
          {verifyOut || "(no verify yet)"}
        </pre>
      </div>

      <div className="panel">
        <h2>Result</h2>
        <p className="muted">Paste direct handoff JSON and run (legacy quick mode).</p>
        <textarea
          style={{ width: "100%", minHeight: "120px", fontFamily: "ui-monospace, monospace", fontSize: "0.78rem" }}
          placeholder='{"anchor":{"kind":"timestamp","unix_secs":1700000000},"state_root_hex":"..."}'
          value={handoffJson}
          onChange={(e) => setHandoffJson(e.target.value)}
        />
        <div style={{ marginTop: "0.5rem", display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <button type="button" className="btn" disabled={busy || !handoffJson.trim()} onClick={runHandoff}>Run pipeline</button>
          <button type="button" className="btn btn-ghost" disabled={busy} onClick={() => setHandoffJson(JSON.stringify({
            anchor: { kind: "timestamp", unix_secs: Math.floor(Date.now() / 1000) },
            state_root_hex: DEFAULT_HEX32,
            rollup_context_digest_hex: DEFAULT_HEX32,
            n: 1,
            k: 0,
            bit_at_k: 0,
            challenge_hex: DEFAULT_HEX32,
          }, null, 2))}>Insert minimal handoff</button>
        </div>
        <pre className="pre-log" style={{ marginTop: "0.75rem", maxHeight: "240px" }}>{out}</pre>
      </div>
    </div>
  );
}
