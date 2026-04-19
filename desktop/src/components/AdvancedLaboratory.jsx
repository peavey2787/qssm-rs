import { useState, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import TemplateBuilder from "./TemplateBuilder";

/** Generate a cryptographically random 32-byte hex salt. */
function generateSaltHex() {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

const DEFAULT_CLAIM_JSON = "";

export default function AdvancedLaboratory() {
  const inTauri = typeof window !== "undefined" && !!window.__TAURI_INTERNALS__?.invoke;
  const [templateJson, setTemplateJson] = useState("");
  const [templateOut, setTemplateOut] = useState("(no template operation yet)");
  const [claimCheckOut, setClaimCheckOut] = useState("(no claim check yet)");
  const [blueprintHex, setBlueprintHex] = useState("");
  const [claimUtf8, setClaimUtf8] = useState(DEFAULT_CLAIM_JSON);
  const [saltHex, setSaltHex] = useState(() => generateSaltHex());
  const [proofHex, setProofHex] = useState("");
  const [apiOut, setApiOut] = useState("(no action yet)");
  const [templatePath, setTemplatePath] = useState("");
  const [showTemplateText, setShowTemplateText] = useState(false);
  const [resetToken, setResetToken] = useState(0);
  const commitRef = useRef({ hex: "", claimUtf8: "", saltHex: "" });
  const [busy, setBusy] = useState(false);

  // Derive template id / title from templateJson for read-only labels
  const parsedTemplate = (() => {
    try {
      const t = JSON.parse(templateJson);
      return { id: t.id || "—", title: t.title || "—" };
    } catch {
      return { id: "—", title: "—" };
    }
  })();

  const onTemplateGenerated = useCallback((json, exampleClaim) => {
    setTemplateJson(json);
    if (exampleClaim) setClaimUtf8(exampleClaim);
  }, []);

  const resetAll = useCallback(() => {
    setTemplateJson("");
    setTemplateOut("(no template operation yet)");
    setClaimCheckOut("(no claim check yet)");
    setBlueprintHex("");
    setClaimUtf8(DEFAULT_CLAIM_JSON);
    setSaltHex(generateSaltHex());
    setProofHex("");
    setApiOut("(no action yet)");
    setTemplatePath("");
    setShowTemplateText(false);
    commitRef.current = { hex: "", claimUtf8: "", saltHex: "" };
    setResetToken((prev) => prev + 1);
  }, []);

  async function runAction(action) {
    if (!inTauri) {
      setApiOut("Rust command bridge unavailable. Launch via npm run tauri:dev.");
      return;
    }
    setBusy(true);
    try {
      await action();
    } catch (error) {
      setApiOut(String(error));
    } finally {
      setBusy(false);
    }
  }

  async function importTemplate() {
    if (!inTauri) {
      setTemplateOut("Rust command bridge unavailable. Launch via npm run tauri:dev.");
      return;
    }
    try {
      const path = await open({
        multiple: false,
        directory: false,
        filters: [{ name: "QSSM templates", extensions: ["qssm", "json"] }],
      });
      if (!path || Array.isArray(path)) {
        return;
      }
      const json = await invoke("import_qssm_template", { path });
      setTemplateJson(json);
      setTemplatePath(path);
      setTemplateOut(`Imported ${path}`);
    } catch (error) {
      setTemplateOut(String(error));
    }
  }

  async function exportTemplate() {
    if (!templateJson.trim()) {
      setTemplateOut("Build, load, or paste template JSON first.");
      return;
    }
    if (!inTauri) {
      setTemplateOut("Rust command bridge unavailable. Launch via npm run tauri:dev.");
      return;
    }
    try {
      const path = await save({
        defaultPath: parsedTemplate.id !== "—" ? `${parsedTemplate.id}.qssm` : "template.qssm",
        filters: [{ name: "QSSM templates", extensions: ["qssm"] }],
      });
      if (!path) {
        return;
      }
      await invoke("export_qssm_template", {
        path,
        templateJson,
      });
      setTemplatePath(path);
      setTemplateOut(`Exported ${path}`);
    } catch (error) {
      setTemplateOut(String(error));
    }
  }

  async function compileBlueprint() {
    await runAction(async () => {
      const templateSource = templateJson.trim();
      if (!templateSource) {
        setApiOut("Load or build a template first.");
        return;
      }
      const result = await invoke("compile_blueprint", { templateSource });
      setBlueprintHex(result);
      setApiOut("Built template into opaque blueprint bytes.");
    });
  }

  async function commitSecret() {
    await runAction(async () => {
      const result = await invoke("commit_secret", {
        secretUtf8: claimUtf8,
        saltHex,
      });
      commitRef.current = { hex: result, claimUtf8, saltHex };
      setApiOut(JSON.stringify({ commitment_hex: result }, null, 2));
    });
  }

  async function proveClaim() {
    await runAction(async () => {
      const result = await invoke("prove_claim", {
        claimUtf8,
        saltHex,
        blueprintHex,
      });
      setProofHex(result);
      setApiOut("Generated proof bytes.");
    });
  }

  async function verifyProof() {
    await runAction(async () => {
      const result = await invoke("verify_proof", {
        proofHex,
        blueprintHex,
      });
      setApiOut(result ? "Pass \u2714 \u2014 verified" : "Failed \u2718 \u2014 requirement not met");
    });
  }

  async function openSecret() {
    await runAction(async () => {
      const result = await invoke("open_secret", {
        secretUtf8: claimUtf8,
        saltHex,
      });
      const snap = commitRef.current;
      const inputChanged =
        snap.hex && (claimUtf8 !== snap.claimUtf8 || saltHex !== snap.saltHex);
      setApiOut(
        JSON.stringify(
          {
            secret: claimUtf8,
            salt_hex: saltHex,
            opened_commitment_hex: result,
            matches_latest_commit: snap.hex ? result === snap.hex : null,
            ...(inputChanged
              ? { warning: "Input or salt changed since the last commit." }
              : {}),
          },
          null,
          2,
        ),
      );
    });
  }

  async function verifyClaimAgainstTemplate() {
    if (!templateJson.trim()) {
      setClaimCheckOut("Load or paste template JSON first.");
      return;
    }
    if (!inTauri) {
      setClaimCheckOut("Rust command bridge unavailable. Launch via npm run tauri:dev.");
      return;
    }
    setBusy(true);
    try {
      const result = await invoke("verify_claim_with_template", {
        templateJson,
        claimJson: claimUtf8,
      });
      const parsed = typeof result === "string" ? JSON.parse(result) : result;
      setClaimCheckOut(parsed.detail ?? "(no result)");
    } catch (error) {
      setClaimCheckOut(String(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="lab-wrap">
      <TemplateBuilder onGenerate={onTemplateGenerated} onResetAll={resetAll} resetToken={resetToken} />

      <div className="panel">
        <h2>Template import and export</h2>
        <p className="muted">
          Load a built-in example, import an existing <code>.qssm</code> file,
          edit the JSON directly, and export it back out.
        </p>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem", alignItems: "end" }}>
          <button type="button" className="btn btn-ghost" onClick={importTemplate}>
            Import .qssm
          </button>
          <button type="button" className="btn btn-ghost" onClick={exportTemplate}>
            Export .qssm
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => setShowTemplateText((prev) => !prev)}
          >
            {showTemplateText ? "Hide template text" : "Show template text"}
          </button>
        </div>
        {templatePath ? (
          <p className="muted" style={{ marginTop: "0.6rem" }}>
            Last file path: <code>{templatePath}</code>
          </p>
        ) : null}
        {showTemplateText ? (
          <textarea
            style={{ marginTop: "0.75rem", minHeight: "220px", fontFamily: "ui-monospace, monospace", fontSize: "0.78rem" }}
            value={templateJson}
            onChange={(event) => setTemplateJson(event.target.value)}
            placeholder='{"qssm_template_version":1,"id":"age-gate-21"}'
          />
        ) : null}
        <pre className="pre-log" style={{ marginTop: "0.75rem", maxHeight: "120px" }}>
          {templateOut}
        </pre>
      </div>

      <div className="panel">
        <h2>Witness &amp; Proof Tester</h2>
        <p className="muted">
          The witness is your secret claim + salt + template. Run the full cycle:
          compile &rarr; commit &rarr; prove &rarr; verify &rarr; open.
        </p>

        {/* Read-only template id / title labels */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", marginBottom: "0.75rem" }}>
          <label className="muted">
            Template id
            <span className="label-value">{parsedTemplate.id}</span>
          </label>
          <label className="muted">
            Template title
            <span className="label-value">{parsedTemplate.title}</span>
          </label>
        </div>

        {/* Salt with auto-generate */}
        <label className="muted" style={{ display: "block" }}>
          Salt hex (32 bytes)
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <input
              value={saltHex}
              onChange={(event) => setSaltHex(event.target.value)}
              style={{ flex: 1, fontFamily: "ui-monospace, monospace", fontSize: "0.78rem" }}
            />
            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => setSaltHex(generateSaltHex())}
              title="Generate new random salt"
              style={{ whiteSpace: "nowrap", padding: "0.35rem 0.6rem", fontSize: "0.8rem" }}
            >
              New salt
            </button>
          </div>
        </label>
        <p className="muted" style={{ marginTop: "0.3rem", fontSize: "0.78rem" }}>
          Auto-generated on load. Keep the same salt across commit, prove, and open for a valid cycle.
        </p>

        <div style={{ marginTop: "0.75rem", display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <button type="button" className="btn" disabled={busy} onClick={compileBlueprint}>
            Build Template
          </button>
          <button type="button" className="btn btn-ghost" disabled={busy} onClick={commitSecret}>
            Commit
          </button>
          <button type="button" className="btn btn-ghost" disabled={busy} onClick={proveClaim}>
            Prove
          </button>
          <button type="button" className="btn btn-ghost" disabled={busy} onClick={verifyProof}>
            Verify
          </button>
          <button type="button" className="btn btn-ghost" disabled={busy} onClick={openSecret}>
            Open
          </button>
        </div>
        <p className="muted" style={{ marginTop: "0.4rem", fontSize: "0.78rem" }}>
          Build Template first. Commit, prove, verify, and open all use the current blueprint generated from the template.
        </p>
        <pre className="pre-log" style={{ marginTop: "0.75rem", maxHeight: "220px" }}>
          {apiOut}
        </pre>
        <button
          type="button"
          className="btn btn-ghost"
          disabled={busy}
          onClick={verifyClaimAgainstTemplate}
          style={{ marginTop: "0.75rem" }}
        >
          Claim check
        </button>
        <label className="muted" style={{ display: "block", marginTop: "0.75rem" }}>
          Claim (secret input as JSON)
          <textarea
            style={{ minHeight: "120px", fontFamily: "ui-monospace, monospace", fontSize: "0.78rem" }}
            value={claimUtf8}
            onChange={(event) => setClaimUtf8(event.target.value)}
          />
        </label>
        <pre className="pre-log" style={{ marginTop: "0.75rem", maxHeight: "140px" }}>
          {claimCheckOut}
        </pre>
        <label className="muted" style={{ display: "block", marginTop: "0.75rem" }}>
          Blueprint hex (read-only after compile)
          <textarea
            readOnly
            style={{ minHeight: "80px", fontFamily: "ui-monospace, monospace", fontSize: "0.78rem", opacity: 0.85 }}
            value={blueprintHex}
          />
        </label>
        <label className="muted" style={{ display: "block", marginTop: "0.75rem" }}>
          Proof hex (read-only after prove)
          <textarea
            readOnly
            style={{ minHeight: "80px", fontFamily: "ui-monospace, monospace", fontSize: "0.78rem", opacity: 0.85 }}
            value={proofHex}
          />
        </label>
      </div>
    </div>
  );
}