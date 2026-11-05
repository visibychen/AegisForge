import type { ArtifactPreview, Capabilities, Health } from '../types/api';

export class ApiError extends Error {
  constructor(message: string, public readonly requestId?: string) {
    super(message);
  }
}

async function get<T>(path: string, token?: string): Promise<T> {
  const response = await fetch(path, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    signal: AbortSignal.timeout(8000),
    cache: 'no-store',
  });
  const data = await response.json();
  if (!response.ok) {
    throw new ApiError(data.error?.message ?? '服务请求失败，请稍后重试。', data.request_id);
  }
  return data as T;
}

export const getHealth = () => get<Health>('/health');
export const getCapabilities = (token: string) => get<Capabilities>('/api/v1/capabilities', token);

export async function uploadArtifact(token: string, kind: string, filename: string, content: Blob): Promise<{ artifact: ArtifactPreview }> {
  const response = await fetch(`/api/v1/artifacts?${new URLSearchParams({ filename, input_type: kind })}`, {
    method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/octet-stream' },
    body: content, signal: AbortSignal.timeout(20000), cache: 'no-store',
  });
  const data = await response.json();
  if (!response.ok) throw new ApiError(data.error?.message ?? '输入提交失败。', data.request_id);
  return data;
}
