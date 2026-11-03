import type { Capabilities, Health } from '../types/api';

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
