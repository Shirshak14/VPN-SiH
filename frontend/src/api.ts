// API payloads are rendered generically; the backend is the schema source of truth.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Json = any;

export interface Analysis {
  id: number;
  filename: string;
  provenance: string;
  status: "queued" | "running" | "done" | "failed";
  stage: string;
  error: string | null;
  created_at: string;
  seconds: number | null;
  summary: Json;
  has_keys: boolean;
}
export interface Sample {
  name: string;
  provenance: string;
  description: string;
  has_keys: boolean;
}

async function req<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, init);
  if (!r.ok) {
    let msg = `${r.status} ${r.statusText}`;
    try {
      const j = await r.json();
      if (j.detail) msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
    } catch {
      /* body was not JSON */
    }
    throw new Error(msg);
  }
  return (r.status === 204 ? undefined : await r.json()) as T;
}

export const api = {
  health: () => req<Json>("/api/health"),
  samples: () => req<Sample[]>("/api/samples"),
  analyses: () => req<Analysis[]>("/api/analyses"),
  analysis: (id: number) => req<Analysis>(`/api/analyses/${id}`),
  tunnels: (id: number) => req<Json[]>(`/api/analyses/${id}/tunnels`),
  tunnel: (id: number, tid: string) => req<Json>(`/api/analyses/${id}/tunnels/${encodeURIComponent(tid)}`),
  remediation: (id: number) => req<Json[]>(`/api/analyses/${id}/remediation`),
  metrics: () => req<Json>("/api/metrics"),
  analyzeSample: (name: string) => req<Analysis>(`/api/samples/${encodeURIComponent(name)}/analyze`, { method: "POST" }),
  upload: (pcap: File, keys: File | null) => {
    const f = new FormData();
    f.append("pcap", pcap);
    if (keys) f.append("keys", keys);
    return req<Analysis>("/api/analyses", { method: "POST", body: f });
  },
  remove: (id: number) => req<void>(`/api/analyses/${id}`, { method: "DELETE" }),
  url: (id: number, what: "report.pdf" | "export.json" | "export.syslog") => `/api/analyses/${id}/${what}`,
};

export const fmtTs = (t: number, t0: number) => `+${(t - t0).toFixed(3)}s`;
export const pct = (v: number | null | undefined) => (v == null ? "n/a" : `${(v * 100).toFixed(1)}%`);
