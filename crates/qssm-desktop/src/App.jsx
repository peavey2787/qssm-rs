import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import CommandMap from "./components/CommandMap.jsx";
import PulseCanvas from "./components/PulseCanvas.jsx";
import MnemonicDisplay from "./components/MnemonicDisplay.jsx";

export default function App() {
  const inTauri = typeof window !== "undefined" && !!window.__TAURI_INTERNALS__?.invoke;
  const [payload, setPayload] = useState(null);
  const [net, setNet] = useState({ online: null, error: null });
  const [tier, setTier] = useState("dashboard");
  const [mustSetup, setMustSetup] = useState(false);
  const [wizardMode, setWizardMode] = useState(null);
  const [wizardStep, setWizardStep] = useState(1);
  const [identityList, setIdentityList] = useState([]);
  const [registryMsg, setRegistryMsg] = useState("");
  const [mnemonic24, setMnemonic24] = useState("");
  const [mnemonicWarn, setMnemonicWarn] = useState("");
  const [verifyIdx, setVerifyIdx] = useState([]);
  const [verifyInput, setVerifyInput] = useState({});
  const [verifyStatus, setVerifyStatus] = useState("");
  const [identityName, setIdentityName] = useState("");
  const [vaultPwd, setVaultPwd] = useState("");
  const [vaultPwd2, setVaultPwd2] = useState("");
  const [actionTarget, setActionTarget] = useState(null);
  const [actionPwd, setActionPwd] = useState("");
  const [revealSeed, setRevealSeed] = useState("");
  const [pulsePhase, setPulsePhase] = useState(0);
  const [hiredStorage, setHiredStorage] = useState([]);

  useEffect(() => {
    if (!inTauri) {
      setNet({
        online: false,
        error: "Running in browser dev server only. Start with `cargo tauri dev`.",
      });
      return () => {};
    }
    const unsubs = [];
    let cancelled = false;
    (async () => {
      const u1 = await listen("command-center", (e) => {
        setPayload(e.payload);
        setPulsePhase((p) => (p + 1) % 1_000_000);
      });
      if (cancelled) {
        u1();
        return;
      }
      unsubs.push(u1);
      const u2 = await listen("network-status", (e) => {
        setNet({
          online: e.payload?.online ?? false,
          error: e.payload?.error ?? null,
        });
      });
      if (cancelled) {
        u2();
        return;
      }
      unsubs.push(u2);
    })();
    return () => {
      cancelled = true;
      unsubs.forEach((u) => typeof u === "function" && u());
    };
  }, [inTauri]);

  useEffect(() => {
    if (!inTauri) return;
    void refreshIdentityList();
    void refreshHiredStorage();
  }, [inTauri]);

  const densityAvg = (payload?.global_density_avg_milli ?? 0) / 1000;
  const realDensity = (payload?.real_density_avg_milli ?? 0) / 1000;
  const harvestPaused = payload?.hardware_harvest_enabled === false;
  const fever = typeof payload?.fever_0_1 === "number" ? payload.fever_0_1 : 0;
  const feverClass = fever > 0.2 || densityAvg < 0.8 ? "fever-high" : "fever-low";
  const isBootstrap = !!payload?.is_bootstrap_mode;
  const pulseLines = useMemo(() => (Array.isArray(payload?.pulses) ? payload.pulses.map(String) : []), [payload, pulsePhase]);
  const localPulseMs = 70 + fever * 110 + (payload?.connected_peers ?? 0) * 3;

  async function refreshIdentityList() {
    try {
      const res = await invoke("list_identities");
      const list = typeof res === "string" ? JSON.parse(res) : res;
      const arr = Array.isArray(list) ? list : [];
      setIdentityList(arr);
      const empty = arr.length === 0;
      setMustSetup(empty);
      if (empty) {
        setTier("identity");
        setWizardMode((m) => m || "create");
        setRegistryMsg("No identity found. Complete setup to continue.");
      }
    } catch (e) {
      setRegistryMsg(String(e));
    }
  }

  async function generateMnemonic() {
    setMnemonicWarn("");
    setVerifyStatus("");
    setVerifyInput({});
    try {
      const res = await invoke("generate_mnemonic_24");
      const j = typeof res === "string" ? JSON.parse(res) : res;
      const phrase = String(j.mnemonic_24 ?? "");
      setMnemonic24(phrase);
      const words = phrase.split(/\s+/).filter(Boolean);
      const picks = new Set();
      while (picks.size < 3 && words.length >= 3) picks.add(Math.floor(Math.random() * words.length));
      setVerifyIdx([...picks].sort((a, b) => a - b));
      setWizardStep(2);
      setMnemonicWarn("Security warning: write this offline. Never screenshot or cloud-store the recovery phrase.");
    } catch (e) {
      setMnemonicWarn(String(e));
    }
  }

  async function validateImportedMnemonic() {
    if (!mnemonic24.trim()) return setVerifyStatus("Enter the 24-word phrase first.");
    try {
      const res = await invoke("validate_mnemonic_24", { mnemonic24 });
      const j = typeof res === "string" ? JSON.parse(res) : res;
      setVerifyStatus(`Valid BIP39 checksum. Derived PeerID: ${j.public_peer_id}`);
      setWizardStep(3);
    } catch (e) {
      setVerifyStatus(`Invalid phrase: ${String(e)}`);
    }
  }

  async function copyMnemonic(text) {
    await navigator.clipboard.writeText(text);
    setRegistryMsg("Copied to clipboard. Clear clipboard after use.");
  }

  function wipeMnemonicFromMemory() {
    const words = mnemonic24.split(/\s+/).filter(Boolean);
    if (words.length) setMnemonic24(words.map((w) => "x".repeat(w.length)).join(" "));
    setTimeout(() => {
      setMnemonic24("");
      setVerifyIdx([]);
      setVerifyInput({});
      setVerifyStatus("");
    }, 0);
  }

  function verifyMnemonicWords() {
    const words = mnemonic24.split(/\s+/).filter(Boolean);
    const ok = verifyIdx.every((idx) => ((verifyInput[idx] ?? "").trim().toLowerCase() || "") === ((words[idx] ?? "").toLowerCase() || ""));
    if (!ok) return setVerifyStatus("Verification failed. Re-check your written words.");
    setVerifyStatus("Verified.");
    setWizardStep(3);
  }

  async function createIdentityFromWizard() {
    if (!mnemonic24) return setRegistryMsg("Provide a mnemonic first.");
    if (!identityName.trim()) return setRegistryMsg("Identity name is required.");
    if (vaultPwd.length < 8 || vaultPwd !== vaultPwd2) return setRegistryMsg("Set matching vault passwords (min 8 chars).");
    try {
      await invoke("create_identity_from_mnemonic", { idName: identityName.trim(), mnemonic24, password: vaultPwd });
      wipeMnemonicFromMemory();
      setIdentityName("");
      setVaultPwd("");
      setVaultPwd2("");
      setWizardStep(1);
      setWizardMode(null);
      await refreshIdentityList();
      setTier("dashboard");
      setRegistryMsg("Identity saved.");
    } catch (e) {
      setRegistryMsg(String(e));
    }
  }

  async function runIdentityAction(kind, identityId) {
    if (!actionPwd) return setRegistryMsg("Password required.");
    try {
      if (kind === "activate") {
        await invoke("activate_identity", { id: identityId, pwd: actionPwd });
      } else if (kind === "reveal") {
        const res = await invoke("decrypt_identity", { id: identityId, pwd: actionPwd });
        const j = typeof res === "string" ? JSON.parse(res) : res;
        setRevealSeed(String(j.mnemonic_24 ?? ""));
      } else if (kind === "delete") {
        await invoke("delete_identity", { id: identityId, pwd: actionPwd });
        setRevealSeed("");
        await refreshIdentityList();
      }
    } catch (e) {
      setRegistryMsg(String(e));
    } finally {
      setActionPwd("");
      setActionTarget(null);
    }
  }

  async function setHarvest(on) {
    try {
      await invoke("toggle_hardware_harvest", { enabled: on });
    } catch (e) {
      setRegistryMsg(String(e));
    }
  }

  async function refreshHiredStorage() {
    try {
      const res = await invoke("list_hired_storage");
      const list = typeof res === "string" ? JSON.parse(res) : res;
      setHiredStorage(Array.isArray(list) ? list : []);
    } catch (e) {
      setRegistryMsg(String(e));
    }
  }

  async function hireFromWelcomeCrew() {
    const provider = payload?.primary_peers?.[0];
    if (!provider) return setRegistryMsg("No Welcome Crew provider available yet.");
    try {
      await invoke("hire_storage_provider", {
        providerPeerId: provider,
        leaseLabel: `lease-${Date.now()}`,
      });
      await refreshHiredStorage();
    } catch (e) {
      setRegistryMsg(String(e));
    }
  }

  async function repairState() {
    if (!payload?.peer_id) return setRegistryMsg("PeerID unavailable for repair.");
    try {
      await invoke("repair_state", { peerId: payload.peer_id });
      setRegistryMsg("Repair request broadcasted to Librarian nodes.");
    } catch (e) {
      setRegistryMsg(String(e));
    }
  }

  return (
    <div className={`app-shell ${feverClass}`}>
      <header className="top-bar">
        <div className="brand">
          QSSM Pulse — Testnet-1{" "}
          <span className="status-pill warn" style={{ marginLeft: "0.45rem" }}>
            {payload?.network_label || "TESTNET-1"}
          </span>
        </div>
        <nav className="nav-tabs" aria-label="Primary">
          {!mustSetup && <button type="button" className={tier === "dashboard" ? "active" : ""} onClick={() => setTier("dashboard")}>Dashboard</button>}
          {!mustSetup && <button type="button" className={tier === "storage" ? "active" : ""} onClick={() => setTier("storage")}>Hired Storage</button>}
          <button type="button" className={tier === "identity" ? "active" : ""} onClick={() => setTier("identity")}>Manage Sovereign ID</button>
        </nav>
        <div className="toggles">
          <span className={`status-pill ${net.online ? "ok" : net.online === false ? "err" : ""}`} title={net.error || ""}>
            {net.online === null ? "Network …" : net.online ? "Mesh online" : "Network offline"}
          </span>
        </div>
      </header>

      {tier === "dashboard" && !mustSetup && (
        <div className="main-grid">
          <CommandMap payload={payload} localPulseMs={localPulseMs + (pulsePhase % 40)} />
          <aside className="pulse-col">
            <div className="pulse-header">Pulse stream</div>
            <PulseCanvas lines={pulseLines} />
            <div style={{ padding: "0.5rem 0.75rem", fontSize: "0.72rem", color: "var(--muted)", borderTop: "1px solid var(--border)" }}>
              Density avg: <strong style={{ color: "var(--text)" }}>{payload?.global_density_avg_milli != null ? densityAvg.toFixed(3) : "—"}</strong>
              {isBootstrap && <span className="status-pill warn" style={{ marginLeft: "0.4rem" }}>Bootstrap Active</span>}
              {isBootstrap && <span className={`ghost-density ${harvestPaused ? "paused" : ""}`}> (Real: {realDensity.toFixed(3)})</span>}
              {" "}· Reputation: <strong style={{ color: "var(--text)" }}>{payload?.local_merit_tier || "Seedling"}</strong>
              {" "}· Governor: <span className={`status-pill ${(payload?.governor_state || "Expanding") === "Defending" ? "err" : "ok"}`}>{payload?.governor_state || "Expanding"}</span>
              {" "}· SMT Root: <strong style={{ color: "var(--text)" }}>{payload?.smt_root_hex || "-"}</strong>
              {" "}· {payload?.proof_verified ? <span className="status-pill ok">Proof Verified</span> : <span className="status-pill err">Proof Not Verified</span>}
              {payload?.fraud_alert_message && (
                <>
                  {" "}· <span className="status-pill fraud">Fraud Alert</span>
                </>
              )}
              {" "}
              <button type="button" className="btn btn-ghost" style={{ marginLeft: "0.35rem", padding: "0.18rem 0.45rem", fontSize: "0.72rem" }} onClick={repairState}>
                Repair State
              </button>
              {payload?.fraud_alert_message && (
                <div style={{ marginTop: "0.35rem", color: "#c8a2ff" }}>{payload.fraud_alert_message}</div>
              )}
            </div>
          </aside>
        </div>
      )}

      {tier === "storage" && !mustSetup && (
        <div className="vault-panel">
          <div className="panel">
            <h2>Hired Storage</h2>
            <p className="muted">Lease manager for provider nodes and recurring rent.</p>
            <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
              <button type="button" className="btn" onClick={hireFromWelcomeCrew}>Hire New Provider</button>
              <button type="button" className="btn btn-ghost" onClick={refreshHiredStorage}>Refresh</button>
            </div>
          </div>
          <div className="panel">
            <h2>Active Leases</h2>
            {hiredStorage.length === 0 ? (
              <p className="muted">No hired providers yet.</p>
            ) : (
              <div style={{ display: "grid", gap: "0.5rem" }}>
                {hiredStorage.map((lease, idx) => (
                  <div key={`${lease.provider_peer_id}-${idx}`} className="panel" style={{ margin: 0, padding: "0.65rem" }}>
                    <div><strong>{lease.lease_label || `lease-${idx + 1}`}</strong></div>
                    <div className="muted">Provider PeerID: {lease.provider_peer_id}</div>
                    <div className="muted">Rent Due: {lease.rent_due || "pending_epoch_1024"}</div>
                    <div className="muted">Status: {lease.status || "active"}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {tier === "identity" && (
        <div className="vault-panel">
          <div className="panel">
            <h2>Identity Management</h2>
            <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
              <button type="button" className="btn" onClick={() => { setWizardMode("create"); setWizardStep(1); setMnemonic24(""); setVerifyStatus(""); }}>Create New ID</button>
              <button type="button" className="btn btn-ghost" onClick={() => { setWizardMode("import"); setWizardStep(1); setMnemonic24(""); setVerifyStatus(""); }}>Import ID</button>
            </div>
            {wizardMode && <div className="muted" style={{ marginTop: "0.55rem" }}>Step {wizardStep} / 3</div>}
            {wizardMode === "create" && wizardStep === 1 && <button type="button" className="btn" style={{ marginTop: "0.5rem" }} onClick={generateMnemonic}>Generate 24-word mnemonic</button>}
            {wizardMode === "import" && wizardStep === 1 && (
              <label className="muted" style={{ display: "flex", flexDirection: "column", gap: "0.35rem", marginTop: "0.5rem" }}>
                Paste existing 24-word recovery phrase
                <textarea value={mnemonic24} onChange={(e) => setMnemonic24(e.target.value)} placeholder="word1 word2 ... word24" style={{ minHeight: "88px", fontFamily: "ui-monospace, monospace" }} />
                <button type="button" className="btn" onClick={validateImportedMnemonic}>Validate & Derive PeerID</button>
              </label>
            )}
            {mnemonicWarn && <div className="security-warn" style={{ marginTop: "0.5rem" }}>{mnemonicWarn}</div>}
            {wizardMode === "create" && mnemonic24 && wizardStep <= 2 && (
              <div style={{ marginTop: "0.6rem" }}>
                <MnemonicDisplay mnemonic={mnemonic24} highlightIndices={wizardStep === 2 ? verifyIdx : []} showCopy onCopy={() => copyMnemonic(mnemonic24)} />
                <p className="muted">Verify by entering 3 highlighted words:</p>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "0.5rem" }}>
                  {verifyIdx.map((idx) => (
                    <label key={idx} className="muted" style={{ display: "flex", flexDirection: "column", gap: "0.25rem" }}>
                      Word #{idx + 1}
                      <input value={verifyInput[idx] ?? ""} onChange={(e) => setVerifyInput((p) => ({ ...p, [idx]: e.target.value }))} />
                    </label>
                  ))}
                </div>
                <button type="button" className="btn" style={{ marginTop: "0.6rem" }} onClick={verifyMnemonicWords}>Verify backup words</button>
              </div>
            )}
            {verifyStatus && <div className="muted" style={{ marginTop: "0.5rem" }}>{verifyStatus}</div>}
            {wizardMode && wizardStep === 3 && (
              <div style={{ marginTop: "0.7rem", display: "grid", gap: "0.5rem" }}>
                <label className="muted" style={{ display: "flex", flexDirection: "column", gap: "0.25rem" }}>Identity name<input value={identityName} onChange={(e) => setIdentityName(e.target.value)} /></label>
                <label className="muted" style={{ display: "flex", flexDirection: "column", gap: "0.25rem" }}>Vault password<input type="password" value={vaultPwd} onChange={(e) => setVaultPwd(e.target.value)} /></label>
                <label className="muted" style={{ display: "flex", flexDirection: "column", gap: "0.25rem" }}>Confirm password<input type="password" value={vaultPwd2} onChange={(e) => setVaultPwd2(e.target.value)} /></label>
                <button type="button" className="btn" onClick={createIdentityFromWizard}>Save Identity</button>
              </div>
            )}
          </div>

          <div className="panel">
            <h2>Sovereign Registry</h2>
            {identityList.length === 0 ? <p className="muted">No identities yet.</p> : (
              <div style={{ display: "grid", gap: "0.5rem" }}>
                {identityList.map((it) => (
                  <div key={it.id} className="panel" style={{ margin: 0, padding: "0.65rem" }}>
                    <div><strong>{it.id_name}</strong> {payload?.active_identity === it.id && <span className="status-pill ok">Active</span>}</div>
                    <div className="muted">{it.public_peer_id}</div>
                    <div style={{ marginTop: "0.4rem", display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
                      <button type="button" className="btn btn-ghost" onClick={() => setActionTarget({ kind: "activate", id: it.id })}>Activate</button>
                      <button type="button" className="btn btn-ghost" onClick={() => setActionTarget({ kind: "reveal", id: it.id })}>Reveal Seed</button>
                      <button type="button" className="btn btn-ghost" onClick={() => setActionTarget({ kind: "delete", id: it.id })}>Delete (HARD WIPE)</button>
                    </div>
                  </div>
                ))}
              </div>
            )}
            {actionTarget && (
              <div className="security-warn" style={{ marginTop: "0.6rem" }}>
                <div><strong>{actionTarget.kind.toUpperCase()}</strong> requires password confirmation.</div>
                {actionTarget.kind === "delete" && <div style={{ marginTop: "0.35rem" }}>Destructive Action: This is a Hard Wipe. Identity recovery is impossible without your 24-word phrase.</div>}
                <div style={{ marginTop: "0.5rem", display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
                  <input type="password" value={actionPwd} onChange={(e) => setActionPwd(e.target.value)} placeholder="vault password" />
                  <button type="button" className="btn" onClick={() => runIdentityAction(actionTarget.kind, actionTarget.id)}>Confirm</button>
                  <button type="button" className="btn btn-ghost" onClick={() => setActionTarget(null)}>Cancel</button>
                </div>
              </div>
            )}
            {revealSeed && <div style={{ marginTop: "0.6rem" }}><MnemonicDisplay mnemonic={revealSeed} showCopy onCopy={() => copyMnemonic(revealSeed)} /></div>}
            {registryMsg && <div className="muted" style={{ marginTop: "0.5rem" }}>{registryMsg}</div>}
          </div>

          <div className="panel">
            <h2>Controls & Credits</h2>
            <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
              <button type="button" className="btn" onClick={() => setHarvest(true)}>Enable harvest</button>
              <button type="button" className="btn btn-ghost" onClick={() => setHarvest(false)}>Pause harvest</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
