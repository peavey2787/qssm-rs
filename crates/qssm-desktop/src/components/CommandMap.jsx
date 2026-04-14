import { useMemo } from "react";
import { MapContainer, TileLayer, CircleMarker, Polyline } from "react-leaflet";
import "leaflet/dist/leaflet.css";

function hashPeer(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function offsetFromPeer(peerId, mag = 2.8) {
  const h = hashPeer(peerId);
  const u = (h & 0xffff) / 65535;
  const v = ((h >> 16) & 0xffff) / 65535;
  const r = mag * Math.sqrt(u);
  const theta = v * Math.PI * 2;
  return [r * Math.cos(theta), r * Math.sin(theta)];
}

function peerHealth(line) {
  if (/Blacklisted/i.test(line)) return "bad";
  if (/Throttled/i.test(line)) return "warn";
  return "ok";
}

/** @param {{ payload: any, localPulseMs: number }} props */
export default function CommandMap({ payload, localPulseMs }) {
  const lat = payload?.geo?.latitude;
  const lon = payload?.geo?.longitude;
  const center = lat != null && lon != null ? [lat, lon] : [39.8, -86.15];
  const fever = typeof payload?.fever_0_1 === "number" ? payload.fever_0_1 : 0;
  const connected = payload?.connected_peers ?? 0;
  const top = Array.isArray(payload?.top_deficit_peers) ? payload.top_deficit_peers : [];
  const localId = payload?.peer_id ?? "";

  const remoteMarkers = useMemo(() => {
    const out = [];
    for (const row of top) {
      const idx = row.indexOf(":");
      const pid = idx > 0 ? row.slice(0, idx).trim() : row.trim();
      if (!pid || pid === localId) continue;
      const [dlat, dlon] = offsetFromPeer(pid, 3.2);
      out.push({
        id: pid,
        pos: [center[0] + dlat * 0.35, center[1] + dlon * 0.35],
        health: peerHealth(row),
      });
    }
    if (out.length === 0 && connected > 0) {
      for (let i = 0; i < Math.min(connected, 6); i++) {
        const synthetic = `${localId}-mesh-${i}`;
        const [dlat, dlon] = offsetFromPeer(synthetic, 4 + i * 0.4);
        out.push({
          id: synthetic,
          pos: [center[0] + dlat * 0.22, center[1] + dlon * 0.22],
          health: fever > 0.35 ? "warn" : "ok",
        });
      }
    }
    return out;
  }, [top, connected, center, localId, fever]);

  const lines = useMemo(() => {
    if (lat == null || lon == null) return [];
    return remoteMarkers.map((m) => ({
      id: m.id,
      positions: [[lat, lon], m.pos],
      health: m.health,
    }));
  }, [lat, lon, remoteMarkers]);

  const dashSpeed = Math.max(0.2, 1.2 - fever) * (localPulseMs / 80);

  return (
    <div className="map-wrap">
      <MapContainer
        center={center}
        zoom={lat != null ? 6 : 4}
        style={{ height: "100%", width: "100%", minHeight: "420px" }}
        scrollWheelZoom
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        {lat != null && lon != null && (
          <CircleMarker
            center={[lat, lon]}
            radius={10}
            pathOptions={{ color: "#3d9dff", fillColor: "#3d9dff", fillOpacity: 0.35 }}
          />
        )}
        {remoteMarkers.map((m) => (
          <CircleMarker
            key={m.id}
            center={m.pos}
            radius={8}
            pathOptions={{
              color: m.health === "bad" ? "#ff6b6b" : m.health === "warn" ? "#ffb86b" : "#3ddc84",
              fillColor: m.health === "bad" ? "#ff6b6b" : m.health === "warn" ? "#ffb86b" : "#3ddc84",
              fillOpacity: 0.45,
            }}
          />
        ))}
        {lines.map((ln) => (
          <Polyline
            key={ln.id}
            positions={ln.positions}
            pathOptions={{
              color: ln.health === "bad" ? "rgba(255,107,107,0.55)" : "rgba(61,220,132,0.45)",
              weight: 1.2,
              dashArray: `${Math.max(4, 14 - fever * 8)} ${Math.max(6, 18 - localPulseMs / 40)}`,
              lineCap: "round",
              dashOffset: -dashSpeed * 12,
            }}
          />
        ))}
      </MapContainer>
    </div>
  );
}
