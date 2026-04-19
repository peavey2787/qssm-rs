import { useState, useEffect } from "react";
import AdvancedLaboratory from "./components/AdvancedLaboratory.jsx";

export default function App() {
  const [dark, setDark] = useState(() => {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("qssm-theme");
      if (saved) return saved === "dark";
      return window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false;
    }
    return false;
  });
  const [showDetails, setShowDetails] = useState(false);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
    localStorage.setItem("qssm-theme", dark ? "dark" : "light");
  }, [dark]);

  return (
    <div className="app-shell">
      <header className="top-bar">
        <div className="top-bar-left">
          <img src="/qssm-mssq-logo.jpg" alt="QSSM" className="top-bar-logo" />
          <div>
            <div className="brand">QSSM Desktop</div>
            <div className="tagline">Stateless Universal Truth Engine template lab</div>
          </div>
        </div>
        <button
          type="button"
          className="theme-toggle"
          onClick={() => setDark((d) => !d)}
          title={dark ? "Switch to light mode" : "Switch to dark mode"}
        >
          {dark ? "\u2600\uFE0F" : "\uD83C\uDF19"}
        </button>
      </header>
      <main className="main-content">
        <section className="hero panel">
          <h1>Template Lab</h1>
          <p className="muted hero-copy">
            Build or import <code>.qssm</code> templates, then run the full
            compile &rarr; commit &rarr; prove &rarr; verify &rarr; open cycle.
          </p>
          <button
            type="button"
            className="hero-toggle-details"
            onClick={() => setShowDetails((s) => !s)}
          >
            {showDetails ? "Hide instructions \u25B2" : "How to use this app \u25BC"}
          </button>
          {showDetails && (
            <div className="hero-details">
              <ol>
                <li>
                  <strong>Build a template</strong> &mdash; use the Template Builder to chain
                  predicates (range, at-least, compare, in-set) into a custom policy, or load the
                  built-in proof-of-age example.
                </li>
                <li>
                  <strong>Generate JSON</strong> &mdash; click &ldquo;Generate template JSON&rdquo; to
                  populate the template editor and auto-fill the claim input with example values.
                </li>
                <li>
                  <strong>Compile</strong> &mdash; turns the template into an opaque blueprint
                  (byte array) that locks in the rules and entropy.
                </li>
                <li>
                  <strong>Commit</strong> &mdash; hashes your secret claim + salt into a 32-byte
                  commitment. This locks your witness without revealing it.
                </li>
                <li>
                  <strong>Prove</strong> &mdash; generates a zero-knowledge proof that your
                  committed claim satisfies the template&rsquo;s predicates.
                </li>
                <li>
                  <strong>Verify</strong> &mdash; checks the proof against the blueprint.
                  Returns pass or fail.
                </li>
                <li>
                  <strong>Open</strong> &mdash; reveals the commitment so anyone can confirm
                  it matches the original commit. Shows the secret, salt, and commitment together.
                </li>
              </ol>
              <p style={{ marginTop: "0.5rem" }}>
                The salt is auto-generated but you can override it. Keep the same salt across
                commit, prove, and open for the cycle to line up.
              </p>
            </div>
          )}
        </section>
        <AdvancedLaboratory />
      </main>
    </div>
  );
}
