import { afterEach, describe, expect, it, vi } from 'vitest';
import { uploadArtifact } from '../src/api/client';

afterEach(() => { vi.unstubAllGlobals(); });

describe('api client errors', () => {
  it('turns network failures into a friendly message', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
    await expect(uploadArtifact('t', 'source', 'a.py', new Blob(['x']))).rejects.toThrow('无法连接服务，请确认后端已启动。');
  });

  it('never surfaces JSON parser errors from non-JSON responses', async () => {
    const response = { ok: false, status: 502, json: () => Promise.reject(new SyntaxError('Unexpected token <')) };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response));
    await expect(uploadArtifact('t', 'source', 'a.py', new Blob(['x']))).rejects.toThrow('服务请求失败（HTTP 502），请稍后重试。');
  });

  it('keeps the server-provided domain message', async () => {
    const response = { ok: false, status: 422, json: () => Promise.resolve({ error: { message: '文件后缀与输入类型不匹配。' } }) };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response));
    await expect(uploadArtifact('t', 'source', 'a.zip', new Blob(['x']))).rejects.toThrow('文件后缀与输入类型不匹配。');
  });
});
