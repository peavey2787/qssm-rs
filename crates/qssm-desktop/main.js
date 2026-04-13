import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";

const DEFAULT_HEX32 = `${"00".repeat(31)}01`;

const l1El = document.getElementById("l1");
const anchorKindEl = document.getElementById("anchor-kind");
const qrngEl = document.getElementById("qrng");
const latencyEl = document.getElementById("latency");
const outEl = document.getElementById("out");
const dz = document.getElementById("dz");
const fileInput = document.getElementById("file");

const predList = document.getElementById("predicate-list");
const verifyTemplateEl = document.getElementById("verify-template");
const verifyClaimEl = document.getElementById("verify-claim");
const verifyOutEl = document.getElementById("verify-out");

/** Presets map to qssm-gadget `PredicateBlock` JSON (`kind`: compare | range | in_set; compare `op`: gt | lt | eq). */
const TRUTH_GATE_PRESETS = {
  blank: { kind: "compare", field: "", op: "gt", rhs: "0" },
  greater_than: { kind: "compare", field: "claim.value", op: "gt", rhs: "0" },
  less_than: { kind: "compare", field: "claim.value", op: "lt", rhs: "100" },
  age_21: { kind: "range", field: "claim.age_years", min: "21", max: "150" },
};

function initGenericDefaults() {
  document.getElementById("anchor-hex").value = DEFAULT_HEX32;
  document.getElementById("gv-state-root").value = DEFAULT_HEX32;
  document.getElementById("gv-rollup").value = DEFAULT_HEX32;
  document.getElementById("gv-challenge").value = DEFAULT_HEX32;
}

function setHud({ l1_sync, qrng_status, prover_latency_ms, nist_included, entropy_anchor_kind }) {
  l1El.textContent = l1_sync ?? "—";
  anchorKindEl.textContent = entropy_anchor_kind ?? "—";
  if (qrng_status === "nist" || nist_included === true) {
    qrngEl.textContent = "NIST pulse active";
  } else if (qrng_status === "fallback" || nist_included === false) {
    qrngEl.textContent = "Fallback mode (anchor ‖ local floor)";
  } else {
    qrngEl.textContent = qrng_status ?? "—";
  }
  if (typeof prover_latency_ms === "number") {
    latencyEl.textContent = `${prover_latency_ms.toFixed(2)} ms`;
  } else {
    latencyEl.textContent = "—";
  }
}

async function showResult(res) {
  const j = typeof res === "string" ? JSON.parse(res) : res;
  setHud(j);
  outEl.textContent = JSON.stringify(j, null, 2);
  outEl.classList.remove("err");
}

function showErr(e) {
  outEl.textContent = String(e);
  outEl.classList.add("err");
  qrngEl.textContent = "—";
  latencyEl.textContent = "—";
  anchorKindEl.textContent = "—";
}

function buildAnchorFromForm() {
  const mode = document.querySelector('input[name="anchor-mode"]:checked').value;
  const hex = document.getElementById("anchor-hex").value.trim();
  if (mode === "timestamp") {
    const unix = Number.parseInt(document.getElementById("anchor-ts").value, 10);
    if (!Number.isFinite(unix) || unix < 0) {
      throw new Error("Invalid Unix seconds");
    }
    return { kind: "timestamp", unix_secs: unix };
  }
  if (mode === "static_root") {
    return { kind: "static_root", root_hex: hex };
  }
  return { kind: "kaspa", parent_block_id_hex: hex };
}

function buildHandoffFromForm() {
  const anchor = buildAnchorFromForm();
  const localRaw = document.getElementById("gv-local").value.trim();
  const o = {
    anchor,
    state_root_hex: document.getElementById("gv-state-root").value.trim(),
    rollup_context_digest_hex: document.getElementById("gv-rollup").value.trim(),
    n: Number.parseInt(document.getElementById("gv-n").value, 10),
    k: Number.parseInt(document.getElementById("gv-k").value, 10),
    bit_at_k: Number.parseInt(document.getElementById("gv-bit").value, 10),
    challenge_hex: document.getElementById("gv-challenge").value.trim(),
  };
  if (localRaw) {
    o.local_entropy_hex = localRaw;
  }
  return JSON.stringify(o);
}

function addPredicateRow(preset) {
  const row = document.createElement("div");
  row.className = "pred-row";
  const p = preset ?? TRUTH_GATE_PRESETS.blank;
  const kind = p.kind;
  const esc = (s) =>
    String(s)
      .replace(/&/g, "&amp;")
      .replace(/"/g, "&quot;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  row.innerHTML = `
    <label class="field">Gate kind
      <select class="pred-kind">
        <option value="range" ${kind === "range" ? "selected" : ""}>Range (digital law band)</option>
        <option value="compare" ${kind === "compare" ? "selected" : ""}>Compare (Truth Gate)</option>
        <option value="in_set" ${kind === "in_set" ? "selected" : ""}>In set</option>
      </select>
    </label>
    <label class="field">Field (dot path)
      <input type="text" class="pred-field" placeholder="claim.age_years" value="${esc(p.field ?? "")}" />
    </label>
    <button type="button" class="secondary pred-remove">Remove</button>
    <div class="pred-extra" style="grid-column: 1 / -1; display: grid; gap: 0.5rem"></div>
  `;
  predList.appendChild(row);
  const extra = row.querySelector(".pred-extra");
  const kindSel = row.querySelector(".pred-kind");
  const renderExtra = () => {
    const k = kindSel.value;
    if (k === "range") {
      extra.innerHTML = `
        <div class="grid2">
          <label class="field">min (i64) <input type="text" class="pred-min" value="${esc(p.min ?? "21")}" /></label>
          <label class="field">max (i64) <input type="text" class="pred-max" value="${esc(p.max ?? "150")}" /></label>
        </div>`;
    } else if (k === "compare") {
      extra.innerHTML = `
        <div class="grid2">
          <label class="field">Op
            <select class="pred-op">
              <option value="gt">gt (&gt;)</option>
              <option value="lt">lt (&lt;)</option>
              <option value="eq">eq (==)</option>
            </select>
          </label>
          <label class="field">rhs (JSON number)
            <input type="text" class="pred-rhs" value="${esc(p.rhs ?? "0")}" />
          </label>
        </div>`;
      if (p.op) {
        const opEl = extra.querySelector(".pred-op");
        if (opEl) opEl.value = p.op;
      }
    } else {
      extra.innerHTML = `<label class="field">Values (comma-separated integers)
        <input type="text" class="pred-values" value="${esc(p.values ?? "1,2,3")}" /></label>`;
    }
  };
  renderExtra();
  kindSel.addEventListener("change", renderExtra);
  row.querySelector(".pred-remove").addEventListener("click", () => row.remove());
}

function collectPredicates() {
  const out = [];
  for (const row of predList.querySelectorAll(".pred-row")) {
    const kind = row.querySelector(".pred-kind").value;
    const field = row.querySelector(".pred-field").value.trim();
    if (!field) {
      throw new Error("Every Truth Gate needs a non-empty field (dot path).");
    }
    if (kind === "range") {
      const min = Number.parseInt(row.querySelector(".pred-min").value, 10);
      const max = Number.parseInt(row.querySelector(".pred-max").value, 10);
      if (!Number.isFinite(min) || !Number.isFinite(max)) {
        throw new Error(`Invalid range for field ${field}`);
      }
      out.push({ kind: "range", field, min, max });
    } else if (kind === "compare") {
      const op = row.querySelector(".pred-op").value;
      const rhsRaw = row.querySelector(".pred-rhs").value.trim();
      let rhs;
      try {
        rhs = JSON.parse(rhsRaw);
      } catch {
        rhs = Number.parseInt(rhsRaw, 10);
        if (!Number.isFinite(rhs)) {
          throw new Error(`Invalid rhs JSON for ${field}`);
        }
      }
      out.push({ kind: "compare", field, op, rhs });
    } else {
      const vs = row
        .querySelector(".pred-values")
        .value.split(",")
        .map((s) => s.trim())
        .filter(Boolean)
        .map((s) => Number.parseInt(s, 10));
      if (vs.some((n) => !Number.isFinite(n))) {
        throw new Error(`Invalid in_set values for ${field}`);
      }
      out.push({ kind: "in_set", field, values: vs });
    }
  }
  return out;
}

async function buildTemplateObject() {
  const vk = await invoke("lattice_demo_vk_seed_hex");
  return {
    qssm_template_version: 1,
    id: document.getElementById("tpl-id").value.trim() || "template",
    title: document.getElementById("tpl-title").value.trim() || "Template",
    allowed_anchor_kinds: ["kaspa_parent_block", "static_root", "timestamp_unix_secs"],
    predicates: collectPredicates(),
    lattice_vk_seed_hex: vk,
    notes: "Exported from QSSM Desktop — Truth Gates / digital laws (PredicateBlock schema).",
  };
}

// OS file paths from drag-drop (Tauri)
void (async () => {
  try {
    const win = getCurrentWindow();
    await win.onDragDropEvent(async (event) => {
      if (event.payload.type !== "drop") {
        return;
      }
      const paths = event.payload.paths;
      if (!paths?.length) {
        return;
      }
      try {
        outEl.textContent = "Running…";
        const res = await invoke("generate_proof_from_file", { path: paths[0] });
        await showResult(res);
      } catch (e) {
        showErr(e);
      }
    });
  } catch {
    /* not in Tauri webview */
  }
})();

["dragenter", "dragover"].forEach((ev) => {
  dz.addEventListener(ev, (e) => {
    e.preventDefault();
    dz.classList.add("drag");
  });
});
dz.addEventListener("dragleave", () => dz.classList.remove("drag"));
dz.addEventListener("drop", async (e) => {
  e.preventDefault();
  dz.classList.remove("drag");
  const f = e.dataTransfer?.files?.[0];
  if (f) {
    try {
      const text = await f.text();
      outEl.textContent = "Running…";
      const res = await invoke("generate_proof_from_handoff_json", { json: text });
      await showResult(res);
    } catch (err) {
      showErr(err);
    }
  }
});

fileInput.addEventListener("change", async () => {
  const f = fileInput.files?.[0];
  if (!f) {
    return;
  }
  try {
    const text = await f.text();
    outEl.textContent = "Running…";
    const res = await invoke("generate_proof_from_handoff_json", { json: text });
    await showResult(res);
  } catch (e) {
    showErr(e);
  }
});

document.getElementById("gv-run").addEventListener("click", async () => {
  try {
    outEl.textContent = "Running…";
    const json = buildHandoffFromForm();
    const res = await invoke("generate_proof_from_handoff_json", { json });
    await showResult(res);
  } catch (e) {
    showErr(e);
  }
});

document.getElementById("add-pred").addEventListener("click", () => addPredicateRow(TRUTH_GATE_PRESETS.blank));

document.getElementById("truth-add-from-preset").addEventListener("click", () => {
  const pick = document.getElementById("truth-preset-pick").value;
  if (!pick) {
    verifyOutEl.textContent = "Choose a Truth Gate preset from the dropdown first.";
    return;
  }
  addPredicateRow(TRUTH_GATE_PRESETS[pick]);
  document.getElementById("truth-preset-pick").value = "";
  verifyOutEl.textContent = "";
});

document.getElementById("preset-btn-gt").addEventListener("click", () => {
  addPredicateRow(TRUTH_GATE_PRESETS.greater_than);
});

document.getElementById("preset-btn-lt").addEventListener("click", () => {
  addPredicateRow(TRUTH_GATE_PRESETS.less_than);
});

document.getElementById("preset-btn-age").addEventListener("click", () => {
  addPredicateRow(TRUTH_GATE_PRESETS.age_21);
});

document.getElementById("gv-preset-age").addEventListener("click", () => {
  predList.innerHTML = "";
  addPredicateRow(TRUTH_GATE_PRESETS.age_21);
  document.getElementById("tpl-id").value = "proof-of-age-21";
  document.getElementById("tpl-title").value = "Proof of age (21+) — Truth Gate";
});

document.getElementById("gv-export-qssm").addEventListener("click", async () => {
  try {
    const path = document.getElementById("export-path").value.trim();
    if (!path) {
      verifyOutEl.textContent = "Set export path first.";
      return;
    }
    const tpl = await buildTemplateObject();
    const templateData = JSON.stringify(tpl);
    await invoke("export_qssm_template", {
      path,
      templateJson: templateData,
    });
    verifyOutEl.textContent = `Wrote ${path}\n\n${JSON.stringify(tpl, null, 2)}`;
  } catch (e) {
    verifyOutEl.textContent = String(e);
  }
});

document.getElementById("verify-run").addEventListener("click", async () => {
  try {
    const res = await invoke("verify_claim_with_template", {
      templateJson: verifyTemplateEl.value,
      claimJson: verifyClaimEl.value,
    });
    verifyOutEl.textContent = typeof res === "string" ? res : JSON.stringify(res, null, 2);
  } catch (e) {
    verifyOutEl.textContent = String(e);
  }
});

document.getElementById("load-poa-template").addEventListener("click", async () => {
  try {
    const s = await invoke("proof_of_age_template_json");
    verifyTemplateEl.value = s;
    verifyOutEl.textContent = "Loaded proof-of-age Truth Gates template into the left pane.";
  } catch (e) {
    verifyOutEl.textContent = String(e);
  }
});

initGenericDefaults();
l1El.textContent = "Connected to Kaspa Node (mock)";
