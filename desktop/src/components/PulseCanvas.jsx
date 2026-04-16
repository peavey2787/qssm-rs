import { useEffect, useRef } from "react";

const MAX_LINES = 400;
const VISIBLE = 80;

/** High-throughput pulse feed: canvas ring buffer + single RAF paint. */
export default function PulseCanvas({ lines }) {
  const canvasRef = useRef(null);
  const bufRef = useRef([]);
  const rafRef = useRef(0);

  useEffect(() => {
    if (!Array.isArray(lines)) return;
    bufRef.current = lines.slice(-MAX_LINES);
  }, [lines]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const paint = () => {
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      canvas.width = Math.floor(rect.width * dpr);
      canvas.height = Math.floor(rect.height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, rect.width, rect.height);

      const buf = bufRef.current;
      const start = Math.max(0, buf.length - VISIBLE);
      ctx.font = "11px ui-monospace, monospace";
      let y = 14;
      for (let i = start; i < buf.length; i++) {
        const line = buf[i];
        if (/rejected|dropped|Blacklisted|Throttled/i.test(line)) {
          ctx.fillStyle = "#ff9b9b";
        } else if (/local|peer [^ ]+ [a-f0-9]{8}/i.test(line)) {
          ctx.fillStyle = "#9dffb5";
        } else {
          ctx.fillStyle = "#c8d6e5";
        }
        ctx.fillText(line, 8, y);
        y += 14;
        if (y > rect.height - 6) break;
      }
      rafRef.current = requestAnimationFrame(paint);
    };
    rafRef.current = requestAnimationFrame(paint);
    return () => cancelAnimationFrame(rafRef.current);
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        flex: 1,
        width: "100%",
        minHeight: "200px",
        display: "block",
      }}
    />
  );
}
