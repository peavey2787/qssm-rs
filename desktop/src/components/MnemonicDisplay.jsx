export default function MnemonicDisplay({
  mnemonic = "",
  highlightIndices = [],
  showCopy = false,
  onCopy,
}) {
  const words = String(mnemonic)
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  if (words.length === 0) {
    return null;
  }
  const hs = new Set(highlightIndices || []);
  return (
    <div>
      <div className="mn-grid">
        {words.map((w, i) => (
          <div key={`${w}-${i}`} className={`mn-word ${hs.has(i) ? "hl" : ""}`}>
            <span className="mn-num">{i + 1}.</span> <span>{w}</span>
          </div>
        ))}
      </div>
      {showCopy && (
        <button type="button" className="btn btn-ghost" style={{ marginTop: "0.55rem" }} onClick={onCopy}>
          Copy to Clipboard
        </button>
      )}
    </div>
  );
}
