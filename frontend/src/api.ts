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
  label: string | null;
  private: boolean;  // owned by a signed-in user (vs the shared demo space)
}
export interface User {
  id: number;
  email: string;
  created_at: string;
}
export interface AccountState {
  registration_open: boolean;
  user: User | null;
}
export interface SamplePreview {
  tunnels: number;
  violations: number;
  top_score: number | null;
  top_band: string | null;
  anomalous: number;
  rules: { rule_id: string; severity: string }[];
  rule_count: number;
}
export interface Sample {
  name: string;
  provenance: string;
  description: string;
  has_keys: boolean;
  title: string;
  story: string;
  kind: string;
  order: number;
  preview: SamplePreview | null;
  input?: "pcap" | "log";
}

export interface AuthState {
  required: boolean;
  authenticated: boolean;
  role: "admin" | "readonly" | null;
}
export const AUTH_EVENT = "ipsec-auth-required";

async function req<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, init);
  if (r.status === 401 && !url.startsWith("/api/login")) window.dispatchEvent(new Event(AUTH_EVENT));
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

const jsonInit = (method: string, body: unknown): RequestInit => ({ method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

export const api = {
  auth: () => req<AuthState>("/api/auth"),
  login: (key: string) => req<{ role: string }>("/api/login", jsonInit("POST", { key })),
  logout: () => req<{ ok: boolean }>("/api/logout", { method: "POST" }),
  account: () => req<AccountState>("/api/account"),
  register: (email: string, password: string) => req<{ user: User }>("/api/account/register", jsonInit("POST", { email, password })),
  signIn: (email: string, password: string) => req<{ user: User }>("/api/account/login", jsonInit("POST", { email, password })),
  signOut: () => req<{ ok: boolean }>("/api/account/logout", { method: "POST" }),
  changePassword: (current: string, next: string) => req<{ ok: boolean }>("/api/account/password", jsonInit("POST", { current, new: next })),
  deleteAccount: (password: string) => req<void>("/api/account", jsonInit("DELETE", { password })),
  rename: (id: number, label: string) => req<Analysis>(`/api/analyses/${id}`, jsonInit("PATCH", { label })),
  samples: () => req<Sample[]>("/api/samples"),
  analyses: () => req<Analysis[]>("/api/analyses"),
  analysis: (id: number) => req<Analysis>(`/api/analyses/${id}`),
  tunnels: (id: number) => req<Json[]>(`/api/analyses/${id}/tunnels`),
  tunnel: (id: number, tid: string) => req<Json>(`/api/analyses/${id}/tunnels/${encodeURIComponent(tid)}`),
  remediation: (id: number) => req<Json[]>(`/api/analyses/${id}/remediation`),
  compare: (before: number, after: number) => req<Json>(`/api/compare?before=${before}&after=${after}`),
  policy: () => req<Json>("/api/policy"),
  metrics: () => req<Json>("/api/metrics"),
  analyzeSample: (name: string) => req<Analysis>(`/api/samples/${encodeURIComponent(name)}/analyze`, { method: "POST" }),
  upload: (pcap: File, keys: File | null) => {
    const f = new FormData();
    f.append("pcap", pcap);
    if (keys) f.append("keys", keys);
    return req<Analysis>("/api/analyses", { method: "POST", body: f });
  },
  uploadLog: (log: File) => {
    const f = new FormData();
    f.append("log", log);
    return req<Analysis>("/api/logs", { method: "POST", body: f });
  },
  ingest: () => req<Json>("/api/ingest/status"),
  remove: (id: number) => req<void>(`/api/analyses/${id}`, { method: "DELETE" }),
  url: (id: number, what: "report.pdf" | "report.html" | "report.html?download=1" | "export.json" | "export.syslog") => `/api/analyses/${id}/${what}`,
};

export const fmtTs = (t: number, t0: number) => `+${(t - t0).toFixed(3)}s`;
export const pct = (v: number | null | undefined) => (v == null ? "n/a" : `${(v * 100).toFixed(1)}%`);

/** Packet captures go to /api/analyses; anything else is treated as a strongSwan daemon log. */
export const isCapture = (name: string) => /\.(pcap|pcapng|cap)$/i.test(name);
