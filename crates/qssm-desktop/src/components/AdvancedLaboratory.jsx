import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

const DEFAULT_HEX32 = `${"00".repeat(31)}01`;

/**
 * Advanced NIZK / .qssm laboratory (lazy-loaded). Core flows only; extend as needed.
 */
export default function AdvancedLaboratory() {
  const inTauri = typeof window !== "undefined" && !!window.__TAURI_INTERNALS__?.invoke;
  const [handoffJson, setHandoffJson] = useState("");
  const [out, setOut] = useState("(no run yet)");
  const [busy, setBusy] = useState(false);
  const [templateJson, setTemplateJson] = useState("");
  const [claimJson, setClaimJson] = useState('{"claim":{"age_years":22}}');
  const [verifyOut, setVerifyOut] = useState("");

  async function runHandoff() {
    if (!inTauri) {
      setOut("Rust command bridge unavailable. Launch via `cargo tauri dev`.");
      return;
    }
    setBusy(true);
    try {
      const res = await invoke("generate_proof_from_handoff_json", { json: handoffJson });
      setOut(typeof res === "string" ? res : JSON.stringify(res, null, 2));
    } catch (e) {
      setOut(String(e));
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

  async function exportQssm(path, tpl) {
    if (!inTauri) {
      throw new Error("Rust command bridge unavailable. Launch via `cargo tauri dev`.");
    }
    await invoke("export_qssm_template", { path, templateJson: tpl });
  }

  return (
    <div className="lab-wrap">
      <div className="panel">
        <h2>Rollup handoff → sovereign + lattice</h2>
        <p className="muted">
          Paste handoff JSON (with <code>anchor</code> or Kaspa fields). Runs the same Phase‑8 + QSSM‑LE
          pipeline as the legacy helper.
        </p>
        <textarea
          style={{ width: "100%", minHeight: "140px", fontFamily: "ui-monospace, monospace", fontSize: "0.8rem" }}
          placeholder='{"anchor":{"kind":"timestamp","unix_secs":1700000000},"state_root_hex":"…", ...}'
          value={handoffJson}
          onChange={(e) => setHandoffJson(e.target.value)}
        />
        <div style={{ marginTop: "0.5rem", display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <button type="button" className="btn" disabled={busy || !handoffJson.trim()} onClick={runHandoff}>
            Run pipeline
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            disabled={busy}
            onClick={() => {
              const o = {
                anchor: { kind: "timestamp", unix_secs: Math.floor(Date.now() / 1000) },
                state_root_hex: DEFAULT_HEX32,
                rollup_context_digest_hex: DEFAULT_HEX32,
                n: 1,
                k: 0,
                bit_at_k: 0,
                challenge_hex: DEFAULT_HEX32,
              };
              setHandoffJson(JSON.stringify(o, null, 2));
            }}
          >
            Insert minimal handoff
          </button>
        </div>
        <pre className="pre-log" style={{ marginTop: "0.75rem", maxHeight: "240px" }}>
          {out}
        </pre>
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
        <h2>Export .qssm</h2>
        <p className="muted">
          Provide an absolute path and a serialized template JSON (use the proof-of-age loader, then edit in the left
          pane above).
        </p>
        <ExportQssmBlock onExport={exportQssm} />
      </div>
    </div>
  );
}

function ExportQssmBlock({ onExport }) {
  const [path, setPath] = useState("");
  const [tpl, setTpl] = useState("");
  const [msg, setMsg] = useState("");
  return (
    <>
      <label className="muted" style={{ display: "flex", flexDirection: "column", gap: "0.35rem" }}>
        Export path (desktop)
        <input value={path} onChange={(e) => setPath(e.target.value)} placeholder="C:\\path\\claim.qssm" />
      </label>
      <label className="muted" style={{ display: "flex", flexDirection: "column", gap: "0.35rem", marginTop: "0.5rem" }}>
        Template JSON
        <textarea
          style={{ minHeight: "100px", fontFamily: "ui-monospace, monospace", fontSize: "0.78rem" }}
          value={tpl}
          onChange={(e) => setTpl(e.target.value)}
        />
      </label>
      <button
        type="button"
        className="btn"
        style={{ marginTop: "0.5rem" }}
        onClick={async () => {
          try {
            if (!path.trim()) {
              setMsg("Set path first.");
              return;
            }
            await onExport(path.trim(), tpl);
            setMsg(`Wrote ${path}`);
          } catch (e) {
            setMsg(String(e));
          }
        }}
      >
        Write .qssm
      </button>
      {msg && (
        <pre className="pre-log" style={{ marginTop: "0.5rem" }}>
          {msg}
        </pre>
      )}
    </>
  );
}
