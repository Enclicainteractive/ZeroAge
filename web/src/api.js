export function getToken() {
  try { return localStorage.getItem('token') || sessionStorage.getItem('token') || ''; } catch { return ''; }
}

export async function request(path, method = 'GET', body, signal) {
  const token = getToken();
  const response = await fetch(`${import.meta.env.VITE_ZEROAGE_API_URL || ''}${path}`, {
    method,
    signal,
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'include',
    cache: 'no-store'
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error || `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return data;
}
