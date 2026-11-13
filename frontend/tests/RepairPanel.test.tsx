import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import RepairPanel from '../src/components/RepairPanel';
import ScanPanel from '../src/components/ScanPanel';
import { ApiError, createRepair, getFindings, getRepair, getScan, listScans, requestValidation } from '../src/api/client';
import type { Gate, Repair, Scan, StoredFinding } from '../src/types/api';

vi.mock('../src/api/client', async importOriginal => {
  const original = await importOriginal<typeof import('../src/api/client')>();
  return {
    ...original, getRepair: vi.fn(), requestValidation: vi.fn(), cancelRepair: vi.fn(), createRepair: vi.fn(),
    getScan: vi.fn(), getFindings: vi.fn(), listScans: vi.fn(), downloadRepair: vi.fn(),
    listRepairs: vi.fn(async () => ({ repairs: [] })), getCompare: vi.fn(),
  };
});

const gate = (id: string, label: string, state: Gate['state'], detail = ''): Gate => ({ id, label, state, detail });
const repair = (over: Partial<Repair> = {}): Repair => ({
  id: 'r1', scan_id: 's1', finding_id: 'f1', source_id: 'a1', source_sha256: 'x', anchor: 'y', candidate_id: 'c1',
  model_alias: 'deepseek', model: 'deepseek-flash', status: 'candidate', error_code: null, diff: '--- original.py\n+++ candidate.py\n',
  validation_status: 'unverified', call_count: 2, simulated: false, dynamic: {}, dynamic_requested: false,
  checks: { mode: 'real', explanation: '使用参数数组', review: { status: 'complete', error: null } },
  impact: { total_lines: 10, changed_lines: 2, added_lines: 3, change_ratio: 0.2, hunks: 1, distance: 0, removed: [],
    signature_changed: [], decorator_changed: [], forbidden_added: [], risky_added: [], imports_added: ['shlex'],
    violations: [], warnings: ['far_edit'] },
  gates: [gate('syntax', '语法校验', 'passed'), gate('target_rules', '目标漏洞已消除（规则）', 'failed', '仍存在：CWE-78 第2行'),
    gate('dynamic_security', '受控动态验证：安全回归', 'skipped', '未请求受控动态验证')],
  ...over,
});

afterEach(() => { window.history.replaceState(null, '', '/'); vi.clearAllMocks(); });

describe('repair panel', () => {
  it('explains why a candidate is not verified through its gate ledger', async () => {
    vi.mocked(getRepair).mockResolvedValue({ repair: repair() });
    render(<RepairPanel token="t" id="r1" />);
    expect(await screen.findByLabelText('修复门禁账本')).toBeInTheDocument();
    expect(screen.getByText('仍存在：CWE-78 第2行')).toBeInTheDocument();
    expect(screen.getByText('未验证')).toBeInTheDocument();
    expect(screen.getByText(/shlex/)).toBeInTheDocument();
    expect(screen.getByText('包含远离漏洞位置的代码改动')).toBeInTheDocument();
  });

  it('never presents a simulated run as verified', async () => {
    vi.mocked(getRepair).mockResolvedValue({ repair: repair({ simulated: true, checks: { mode: 'fake' }, model_alias: 'fake' }) });
    render(<RepairPanel token="t" id="r1" />);
    expect(await screen.findByText(/没有生成真实修复/)).toBeInTheDocument();
    expect(screen.queryByText('受控验证全部通过')).not.toBeInTheDocument();
  });

  it('stops polling and asks to reconnect after an authorization failure', async () => {
    vi.mocked(getRepair).mockRejectedValue(new ApiError('访问令牌无效或缺失。', undefined, 401));
    render(<RepairPanel token="t" id="r1" />);
    await screen.findByText('会话已失效，请重新连接服务后再查看候选修复。');
    await new Promise(resolve => setTimeout(resolve, 1800));
    expect(getRepair).toHaveBeenCalledTimes(1);
  });

  it('disables the validation request while one is already pending', async () => {
    vi.mocked(getRepair).mockResolvedValue({ repair: repair({ dynamic: { status: 'pending' } }) });
    render(<RepairPanel token="t" id="r1" />);
    const button = await screen.findByRole('button', { name: '申请受控动态验证' });
    expect(button).toBeDisabled();
    expect(screen.getByRole('button', { name: '取消动态验证' })).toBeEnabled();
    expect(requestValidation).not.toHaveBeenCalled();
  });

  it('ignores a repair that belongs to another scan', async () => {
    vi.mocked(getRepair).mockResolvedValue({ repair: repair({ scan_id: 'other' }) });
    render(<RepairPanel token="t" id="r1" scanId="s1" />);
    expect(await screen.findByText('该候选修复不属于当前检测任务。')).toBeInTheDocument();
    expect(screen.queryByLabelText('修复门禁账本')).not.toBeInTheDocument();
  });
});

describe('repair creation', () => {
  const scan = {
    id: 's1', status: 'partial', strategy: 'hybrid', model_alias: 'fake', error_code: null, cancel_requested: false,
    retries: 0, created_at: '', finished_at: '', call_count: 0, result: {},
    artifacts: [{ id: 'a1', display_name: 'app.py', input_type: 'source', sha256: 'abc' }],
  } as unknown as Scan;
  const finding = {
    id: 'f1', category: 'cmdi', cwe: 'CWE-78', severity: 'high', evidence: 'os.system(x)', evidence_truncated: false,
    explanation: 'e', recommendation: 'r', sources: ['rule'], evidence_status: 'potential', contributors: [],
    severity_disagreement: false, location: { kind: 'source', artifact_id: 'a1', start_line: 2, end_line: 2 },
  } as StoredFinding;

  it('reuses one idempotency key until the request succeeds', async () => {
    window.history.replaceState(null, '', '/?scan=s1');
    vi.mocked(listScans).mockResolvedValue({ scans: [], total: 0 });
    vi.mocked(getScan).mockResolvedValue({ scan });
    vi.mocked(getFindings).mockResolvedValue({ findings: [finding], total: 1, attempt: 0 });
    vi.mocked(getRepair).mockResolvedValue({ repair: repair() });
    vi.mocked(createRepair).mockRejectedValueOnce(new ApiError('无法连接服务，请确认后端已启动。'))
      .mockResolvedValueOnce({ repair: repair() });
    render(<ScanPanel token="t" aliases={['fake']} artifacts={[]} onRemove={() => {}} />);
    const button = await screen.findByRole('button', { name: /候选修复/ });
    fireEvent.click(button);
    await screen.findByText('无法连接服务，请确认后端已启动。');
    fireEvent.click(await screen.findByRole('button', { name: /候选修复/ }));
    await screen.findByLabelText('候选修复详情');
    const [first, second] = vi.mocked(createRepair).mock.calls;
    expect(first[4]).toBe(second[4]);
    expect(new URLSearchParams(location.search).get('repair')).toBe('r1');
  });
});
