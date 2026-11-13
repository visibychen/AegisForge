import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import ScanPanel from '../src/components/ScanPanel';
import { ApiError, createScan, getFindings, getScan, listScans } from '../src/api/client';
import type { ArtifactPreview, Scan } from '../src/types/api';

vi.mock('../src/api/client', async importOriginal => {
  const original = await importOriginal<typeof import('../src/api/client')>();
  return {
    ...original, createScan: vi.fn(), getScan: vi.fn(), getFindings: vi.fn(), listScans: vi.fn(), changeScan: vi.fn(),
    listRepairs: vi.fn(async () => ({ repairs: [] })), getInput: vi.fn(),
  };
});

const artifact = { id: 'a1', display_name: 'app.py', input_type: 'source' } as ArtifactPreview;
const scan: Scan = {
  id: 's1', status: 'partial', strategy: 'hybrid', model_alias: 'deepseek', error_code: 'MODEL_TRANSPORT',
  cancel_requested: false, retries: 0, created_at: '', finished_at: '', call_count: 3, artifacts: [],
  budget: { scan_used: 3, scan_limit: 32, daily_used: 3, daily_limit: 64 }, attempt: 0, attempts: [],
  result: { completed_chunks: 1, expected_chunks: 2, coverage: [
    { artifact_id: 'a1', display_name: 'app.py', input_type: 'source', chunk: 0, start_line: 1, end_line: 40,
      rules: 'ran', model: 'succeeded', model_error: null, failure_category: null, llm_findings: 2 },
    { artifact_id: 'a1', display_name: 'app.py', input_type: 'source', chunk: 1, start_line: 38, end_line: 90,
      rules: 'ran', model: 'failed', model_error: 'MODEL_INVALID_OUTPUT', failure_category: 'evidence', llm_findings: 0 },
  ] },
};

afterEach(() => { window.history.replaceState(null, '', '/'); });

describe('scan panel', () => {
  it('reuses one idempotency key until the submission succeeds', async () => {
    vi.mocked(listScans).mockResolvedValue({ scans: [], total: 0 });
    vi.mocked(getScan).mockResolvedValue({ scan: { ...scan, status: 'queued', result: {} } });
    vi.mocked(createScan).mockRejectedValueOnce(new ApiError('无法连接服务，请确认后端已启动。'))
      .mockResolvedValueOnce({ scan: { ...scan, status: 'queued' } });
    render(<ScanPanel token="t" aliases={['fake']} artifacts={[artifact]} onRemove={() => {}} />);
    const button = screen.getByRole('button', { name: /创建检测任务/ });
    fireEvent.click(button);
    await screen.findByText('无法连接服务，请确认后端已启动。');
    fireEvent.click(button);
    await waitFor(() => expect(createScan).toHaveBeenCalledTimes(2));
    const [first, second] = vi.mocked(createScan).mock.calls;
    expect(first[4]).toBe(second[4]);
  });

  it('stops polling and asks to reconnect after an authorization failure', async () => {
    window.history.replaceState(null, '', '/?scan=s1');
    vi.mocked(listScans).mockResolvedValue({ scans: [], total: 0 });
    vi.mocked(getScan).mockReset().mockRejectedValue(new ApiError('访问令牌无效或缺失。', undefined, 401));
    render(<ScanPanel token="t" aliases={['fake']} artifacts={[]} onRemove={() => {}} />);
    await screen.findByText('会话已失效，请重新连接服务后再查看任务。');
    await new Promise(resolve => setTimeout(resolve, 1800));
    expect(getScan).toHaveBeenCalledTimes(1);
  });

  it('shows the per-chunk coverage ledger with its gaps', async () => {
    window.history.replaceState(null, '', '/?scan=s1');
    vi.mocked(listScans).mockResolvedValue({ scans: [], total: 0 });
    vi.mocked(getScan).mockReset().mockResolvedValue({ scan });
    vi.mocked(getFindings).mockResolvedValue({ findings: [], total: 0, attempt: 0 });
    render(<ScanPanel token="t" aliases={['fake']} artifacts={[]} onRemove={() => {}} />);
    expect(await screen.findByLabelText('分析覆盖台账')).toBeInTheDocument();
    expect(screen.getByText(/1 个存在缺口/)).toBeInTheDocument();
    expect(screen.getByText('模型未完成')).toBeInTheDocument();
    expect(screen.getByText('MODEL_INVALID_OUTPUT / evidence')).toBeInTheDocument();
    expect(screen.getByText(/本任务 3\/32/)).toBeInTheDocument();
  });
});
