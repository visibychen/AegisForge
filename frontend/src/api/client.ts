import type {
  ArtifactPreview, Capabilities, CompareView, FindingFacets, FindingFilters, Health, HistoryFilters, HistoryRow,
  InputView, Overview, Repair, Scan, StoredFinding, Strategy,
} from '../types/api';

export class ApiError extends Error {
  constructor(message: string, public readonly requestId?: string, public readonly status?: number) {
    super(message);
  }
}

/** Session is unusable (missing/invalid token): callers should stop polling and ask to reconnect. */
export const isAuthFailure = (error: unknown) =>
  error instanceof ApiError && (error.status === 401 || error.status === 403);

/** The task/repair is gone (for example removed from history): callers stop polling and clear selection. */
export const isGone = (error: unknown) => error instanceof ApiError && error.status === 404;

/** The caller cancelled on purpose (unmount, newer request): never show this as an error. */
export const isAborted = (error: unknown) => error instanceof DOMException && error.name === 'AbortError';

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
export const getScan = (token: string, id: string, signal?: AbortSignal) =>
  request<{scan: Scan}>(`/api/v1/scans/${encodeURIComponent(id)}`, {headers: authorization(token)}, 8000, signal);
export const listScans = (token: string) =>
  request<{scans: Scan[]; total: number}>('/api/v1/scans?limit=10', {headers: authorization(token)}, 8000);
export const FINDING_PAGE = 20;
const query = (params: Record<string, string | number | undefined>) =>
  new URLSearchParams(Object.entries(params).flatMap(([key, value]) => (value === undefined || value === '' ? [] : [[key, String(value)]])));
export const getFindings = (token: string, id: string, offset = 0, filters: FindingFilters = {}, signal?: AbortSignal) =>
  request<{findings: StoredFinding[]; total: number; attempt: number; facets?: FindingFacets}>(
    `/api/v1/scans/${encodeURIComponent(id)}/findings?${query({ offset, limit: FINDING_PAGE, ...filters })}`, {headers: authorization(token)}, 8000, signal);
export const changeScan = (token: string, id: string, action: 'cancel' | 'retry') =>
  request<{scan: Scan}>(`/api/v1/scans/${encodeURIComponent(id)}/${action}`, {method: 'POST', headers: authorization(token)}, 8000);

export const createRepair = (token: string, finding_id: string, source_sha256: string, model_alias: string, key: string) =>
  request<{repair: Repair}>('/api/v1/repairs', {method:'POST',headers:{...authorization(token),'Content-Type':'application/json','Idempotency-Key':key}, body:JSON.stringify({finding_id,source_sha256,model_alias})},20000);
export const getRepair = (token: string, id: string, signal?: AbortSignal) => request<{repair: Repair}>(`/api/v1/repairs/${encodeURIComponent(id)}`,{headers:authorization(token)},8000,signal);
export const cancelRepair = (token: string, id: string) => request<{repair: Repair}>(`/api/v1/repairs/${encodeURIComponent(id)}/cancel`,{method:'POST',headers:authorization(token)},8000);
export const requestValidation = (token: string, id: string) => request<{repair: Repair}>(`/api/v1/repairs/${encodeURIComponent(id)}/validate`,{method:'POST',headers:authorization(token)},8000);
export const listRepairs = (token: string, scanId: string, signal?: AbortSignal) =>
  request<{repairs: Repair[]}>(`/api/v1/repairs?${query({ scan_id: scanId })}`, {headers: authorization(token)}, 8000, signal);
export const getCompare = (token: string, id: string, signal?: AbortSignal) =>
  request<{compare: CompareView}>(`/api/v1/repairs/${encodeURIComponent(id)}/compare`, {headers: authorization(token)}, 15000, signal);
export const getInput = (token: string, scanId: string, artifactId: string, signal?: AbortSignal) =>
  request<{input: InputView}>(`/api/v1/scans/${encodeURIComponent(scanId)}/inputs/${encodeURIComponent(artifactId)}`, {headers: authorization(token)}, 15000, signal);

export const HISTORY_PAGE = 10;
export const getOverview = (token: string, signal?: AbortSignal) =>
  request<Overview>('/api/v1/workspace', {headers: authorization(token)}, 8000, signal);
export const getHistory = (token: string, filters: HistoryFilters, offset: number, signal?: AbortSignal) =>
  request<{scans: HistoryRow[]; total: number}>(`/api/v1/workspace/history?${query({ ...filters, offset, limit: HISTORY_PAGE })}`, {headers: authorization(token)}, 8000, signal);
export const deleteScan = (token: string, id: string) =>
  request<{deleted: boolean; scan_id: string; retained: string}>(`/api/v1/workspace/${encodeURIComponent(id)}/delete`, {method: 'POST', headers: authorization(token)}, 8000);
export async function downloadReport(token: string, id: string, format: 'json' | 'markdown') {
  let response: Response;
  try {
    response = await fetch(`/api/v1/workspace/${encodeURIComponent(id)}/report?format=${format}`, {headers: authorization(token), cache: 'no-store', signal: withTimeout(15000)});
  } catch { throw new ApiError(OFFLINE); }
  if (!response.ok) {
    let message: string | undefined;
    try { message = (await response.json())?.error?.message; } catch { /* a proxy may answer with HTML */ }
    throw new ApiError(message ?? statusMessage(response.status), undefined, response.status);
  }
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement('a');
  link.href = url; link.download = `aegisforge-report-${id.slice(0, 8)}.${format === 'json' ? 'json' : 'md'}`; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export async function downloadRepair(token: string, id: string, format: 'diff' | 'source') {
  const response = await fetch(`/api/v1/repairs/${encodeURIComponent(id)}/download?format=${format}`,{headers:authorization(token),cache:'no-store',signal:AbortSignal.timeout(15000)});
  if (!response.ok) throw new Error('候选下载失败。');
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement('a'); link.href = url; link.download = format === 'diff' ? 'repair.patch' : 'candidate.py'; link.click();
  setTimeout(() => URL.revokeObjectURL(url),1000);
}
