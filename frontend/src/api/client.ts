import type { ArtifactPreview, Capabilities, Health, Scan, StoredFinding, Strategy } from '../types/api';

export class ApiError extends Error {
  constructor(message: string, public readonly requestId?: string, public readonly status?: number) {
    super(message);
  }
}

/** Session is unusable (missing/invalid token): callers should stop polling and ask to reconnect. */
export const isAuthFailure = (error: unknown) =>
  error instanceof ApiError && (error.status === 401 || error.status === 403);

const OFFLINE = '无法连接服务，请确认后端已启动。';

function statusMessage(status: number): string {
  if (status === 401) return '访问令牌无效或已失效，请重新连接。';
  if (status === 413) return '文件超过大小限制。';
  return `服务请求失败（HTTP ${status}），请稍后重试。`;
}

function withTimeout(ms: number, signal?: AbortSignal): AbortSignal | undefined {
  const timeout = typeof AbortSignal.timeout === 'function' ? AbortSignal.timeout(ms) : undefined;
  if (!signal) return timeout;
  if (!timeout || typeof AbortSignal.any !== 'function') return signal;
  return AbortSignal.any([signal, timeout]);
}

async function request<T>(path: string, init: RequestInit, timeoutMs: number, signal?: AbortSignal): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, { ...init, signal: withTimeout(timeoutMs, signal), cache: 'no-store' });
  } catch (exception) {
    if (signal?.aborted) throw exception; // Cancelled by the caller: let it decide what to show.
    const timedOut = exception instanceof DOMException && exception.name === 'TimeoutError';
    throw new ApiError(timedOut ? '请求超时，请缩小输入后重试。' : OFFLINE);
  }
  let data: { error?: { message?: string }; request_id?: string } | null = null;
  try {
    data = await response.json();
  } catch {
    data = null; // Proxies may answer with HTML; never surface parser errors to the user.
  }
  if (!response.ok || !data) {
    throw new ApiError(data?.error?.message ?? statusMessage(response.status), data?.request_id, response.status);
  }
  return data as T;
}

const authorization = (token: string) => ({ Authorization: `Bearer ${token}` });

export const getHealth = () => request<Health>('/health', {}, 8000);
export const getCapabilities = (token: string) =>
  request<Capabilities>('/api/v1/capabilities', { headers: authorization(token) }, 8000);

export function uploadArtifact(
  token: string, kind: string, filename: string, content: Blob, signal?: AbortSignal,
): Promise<{ artifact: ArtifactPreview }> {
  return request<{ artifact: ArtifactPreview }>(`/api/v1/artifacts?${new URLSearchParams({ filename, input_type: kind })}`, {
    method: 'POST',
    headers: { ...authorization(token), 'Content-Type': 'application/octet-stream' },
    body: content,
  }, 20000, signal);
}

export const createScan = (token: string, ids: string[], strategy: Strategy, alias: string, key: string) =>
  request<{scan: Scan}>('/api/v1/scans', {method: 'POST', headers: {...authorization(token),
    'Content-Type': 'application/json', 'Idempotency-Key': key},
    body: JSON.stringify({artifact_ids: ids, strategy, model_alias: alias})}, 20000);
export const getScan = (token: string, id: string) =>
  request<{scan: Scan}>(`/api/v1/scans/${encodeURIComponent(id)}`, {headers: authorization(token)}, 8000);
export const listScans = (token: string) =>
  request<{scans: Scan[]; total: number}>('/api/v1/scans?limit=10', {headers: authorization(token)}, 8000);
export const getFindings = (token: string, id: string, offset = 0) =>
  request<{findings: StoredFinding[]; total: number; attempt: number}>(`/api/v1/scans/${encodeURIComponent(id)}/findings?offset=${offset}&limit=100`, {headers: authorization(token)}, 8000);
export const changeScan = (token: string, id: string, action: 'cancel' | 'retry') =>
  request<{scan: Scan}>(`/api/v1/scans/${encodeURIComponent(id)}/${action}`, {method: 'POST', headers: authorization(token)}, 8000);
