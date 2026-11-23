// Single place the frontend learns the backend URL. NEXT_PUBLIC_API_URL is
// set at build time from VITE_API_BASE_URL (see frontend/next.config.js);
// it falls back to the local dev backend.
export const API_BASE =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export function apiFetch(path: string, init?: RequestInit) {
  return fetch(`${API_BASE}${path}`, init);
}
