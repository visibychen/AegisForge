import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import RepairPanel from '../src/components/RepairPanel';
import ScanPanel from '../src/components/ScanPanel';
import SourceLines from '../src/components/SourceLines';
import Workspace from '../src/components/Workspace';
import {
  ApiError, deleteScan, downloadReport, getCompare, getFindings, getHistory, getInput, getOverview, getRepair, getScan,
  listRepairs,
} from '../src/api/client';
import type { CompareView, HistoryRow, InputView, Overview, Repair, Scan, StoredFinding } from '../src/types/api';

vi.mock('../src/api/client', async importOriginal => {
  const original = await importOriginal<typeof import('../src/api/client')>();
  return {
    ...original, getOverview: vi.fn(), getHistory: vi.fn(), deleteScan: vi.fn(), downloadReport: vi.fn(), getInput: vi.fn(),
    getCompare: vi.fn(), getScan: vi.fn(), getFindings: vi.fn(), listRepairs: vi.fn(), getRepair: vi.fn(), createRepair: vi.fn(),
    changeScan: vi.fn(), createScan: vi.fn(), downloadRepair: vi.fn(), requestValidation: vi.fn(), cancelRepair: vi.fn(),
  };
});

const ID = 'aaaaaaaa-0000-0000-0000-000000000001';
const row = (over: Partial<HistoryRow> = {}): HistoryRow => ({
  id: ID, status: 'completed', strategy: 'rules', mode: 'rules', attempt: 0, error_code: null, created_at: '2026-01-01T00:00:00Z',
  finished_at: null, analysis_complete: true, artifacts: [{ display_name: 'app.py', input_type: 'source' }],
  findings: { total: 2, severities: { high: 2 }, cwes: { 'CWE-78': 2 } }, repairs: { total: 1, simulated: 1, verdicts: { unverified: 1 } },
  ...over,
});
const overview: Overview = {
  tasks: 2, states: { completed: 1, partial: 1 }, modes: { rules: 1, simulated: 1 }, real_outcomes: {},
  cwes: { 'CWE-78': 2 }, severities: { high: 2 },
  repairs: { total: 1, by_status: { candidate: 1 }, simulated: 1, dynamic: { none: 1 }, verdicts: { unverified: 1 }, verdicts_truncated: false },
  notice: '',
};
const finding = (id: string, cwe: string, start: number): StoredFinding => ({
  id, category: 'cmdi', cwe, severity: 'high', evidence: 'os.system(x)', evidence_truncated: false, explanation: 'e', recommendation: 'r',
  sources: ['rule'], evidence_status: 'potential', contributors: [], severity_disagreement: false,
  location: { kind: 'source', artifact_id: 'a1', start_line: start, end_line: start },
});
const scan = {
  id: 's1', status: 'completed', strategy: 'rules', model_alias: 'fake', error_code: null, cancel_requested: false, retries: 0,
  created_at: '', finished_at: '', call_count: 0, result: {}, artifacts: [{ id: 'a1', display_name: 'app.py', input_type: 'source', sha256: 'abc' }],
} as unknown as Scan;
const page = { findings: [finding('f1', 'CWE-78', 2), finding('f2', 'CWE-89', 4)], total: 2, attempt: 0,
  facets: { cwe: { 'CWE-78': 1, 'CWE-89': 1 }, severity: { high: 2 }, source: { rule: 2 }, evidence_status: { potential: 2 } } };
const input: InputView = {
  artifact_id: 'a1', display_name: 'app.py', input_type: 'source', chunk_count: 1, fields: {}, field_meta: {},
  content: "x = '<script>alert(1)</script>'\nos.system(request.args['c'])\n\ncursor.execute(q)\n",
};
const repair = (over: Partial<Repair> = {}): Repair => ({
  id: 'r1', scan_id: 's1', finding_id: 'f1', source_id: 'a1', source_sha256: 'x', anchor: 'y', candidate_id: 'c1',
  model_alias: 'deepseek', model: 'deepseek-flash', status: 'candidate', error_code: null, diff: '--- a\n+++ b\n',
  validation_status: 'unverified', call_count: 2, simulated: false, dynamic: {}, dynamic_requested: false,
  checks: { mode: 'real' }, gates: [{ id: 'syntax', label: '语法校验', state: 'passed', detail: '' }], ...over,
});
const compare: CompareView = {
  repair_id: 'r1', scan_id: 's1', simulated: false, target: { cwe: 'CWE-78', start_line: 2, end_line: 2 },
  original: { sha256: 'a'.repeat(64), content: "import os\nos.system(request.args['c'])\n" },
  candidate: { sha256: 'b'.repeat(64), content: "import subprocess\nsubprocess.run([request.args['c']])\ncursor.execute(q)\n" },
  hunks: [{ old_start: 1, old_end: 2, new_start: 1, new_end: 2 }], baseline: [{ cwe: 'CWE-78', start_line: 2, end_line: 2 }],
  after: { persisting: [], preexisting: [], introduced: [{ cwe: 'CWE-89', start_line: 3, end_line: 3 }] },
};
const deferred = <T,>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
};
const wait = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
const neverSettles = () => new Promise<never>(() => {});

beforeEach(() => {
  vi.mocked(getOverview).mockResolvedValue(overview);
  vi.mocked(getHistory).mockResolvedValue({ scans: [row()], total: 1 });
  vi.mocked(listRepairs).mockResolvedValue({ repairs: [] });
  vi.mocked(getFindings).mockResolvedValue(page);
  vi.mocked(getRepair).mockImplementation(neverSettles);
});
afterEach(() => { window.history.replaceState(null, '', '/'); vi.resetAllMocks(); });

describe('source lines', () => {
  it('renders plain text with line numbers, text tags and keyboard navigation', () => {
    const picked = vi.fn();
    const { container } = render(<SourceLines label="源码" content={input.content} onActivate={picked}
      marks={[{ start: 2, end: 2, kind: 'selected', note: 'CWE-78', id: 'f1' }, { start: 4, end: 4, kind: 'finding', note: 'CWE-89', id: 'f2' }]} />);
    expect(screen.getByText("x = '<script>alert(1)</script>'")).toBeInTheDocument();
    expect(container.querySelector('script')).toBeNull(); // never parsed as HTML
    expect(screen.getByText('当前所选发现 · CWE-78')).toBeInTheDocument();
    const region = screen.getByRole('group', { name: '源码' });
    expect(region).toHaveAttribute('tabindex', '0');
    fireEvent.keyDown(region, { key: 'n' }); // 2 -> next marked line (4)
    expect(region.querySelector('[data-line="4"]')).toHaveAttribute('aria-current', 'true');
    fireEvent.keyDown(region, { key: 'Enter' });
    expect(picked).toHaveBeenCalledWith(expect.objectContaining({ id: 'f2' }));
    fireEvent.keyDown(region, { key: 'p' });
    expect(region.querySelector('[data-line="2"]')).toHaveAttribute('aria-current', 'true');
  });
});

describe('workspace', () => {
  it('shows aggregates by mode without presenting findings as confirmed vulnerabilities', async () => {
    render(<Workspace token="t" />);
    const section = await screen.findByLabelText('任务总览');
    expect(await within(section).findByText('模拟模型（未做真实分析） 1')).toBeInTheDocument();
    expect(within(section).getByText(/不是确认漏洞数或准确率/)).toBeInTheDocument();
    expect(await screen.findByText('仅规则，未做模型分析')).toBeInTheDocument();
    expect(screen.getByText(/候选风险 2 项/)).toBeInTheDocument();
    expect(screen.queryByText(/已确认漏洞/)).not.toBeInTheDocument();
  });

  it('shows empty and not-connected states', async () => {
    vi.mocked(getHistory).mockResolvedValue({ scans: [], total: 0 });
    vi.mocked(getOverview).mockResolvedValue({ ...overview, tasks: 0, states: {}, modes: {}, cwes: {}, severities: {} });
    const { rerender } = render(<Workspace token="" />);
    expect(screen.getByText('连接服务后查看总览与历史。')).toBeInTheDocument();
    rerender(<Workspace token="t" />);
    expect(await screen.findByText(/历史为空/)).toBeInTheDocument();
    expect(await screen.findByText(/还没有检测任务/)).toBeInTheDocument();
  });

  it('asks for confirmation, tells the page about the removal and clears the address', async () => {
    window.history.replaceState(null, '', `/?scan=${ID}&repair=r1`);
    const removed = vi.fn();
    window.addEventListener('aegisforge:deleted', removed);
    vi.mocked(deleteScan).mockResolvedValue({ deleted: true, scan_id: ID, retained: '预算审计保留。' });
    vi.mocked(getHistory).mockResolvedValueOnce({ scans: [row()], total: 1 }).mockResolvedValue({ scans: [], total: 0 });
    render(<Workspace token="t" />);
    fireEvent.click(await screen.findByRole('button', { name: '移出历史 aaaaaaaa' }));
    expect(deleteScan).not.toHaveBeenCalled(); // nothing happens before the explicit confirmation
    fireEvent.click(screen.getByRole('button', { name: '确认移出' }));
    expect(await screen.findByText(/已移出历史。预算审计保留。/)).toBeInTheDocument();
    expect(deleteScan).toHaveBeenCalledWith('t', ID);
    expect(removed).toHaveBeenCalledTimes(1);
    expect((removed.mock.calls[0][0] as CustomEvent).detail).toEqual({ scanId: ID });
    expect(location.search).toBe('');
    expect(await screen.findByText(/历史为空/)).toBeInTheDocument();
    window.removeEventListener('aegisforge:deleted', removed);
  });

  it('does not offer removal while a task is still running', async () => {
    vi.mocked(getHistory).mockResolvedValue({ scans: [row({ status: 'running' })], total: 1 });
    render(<Workspace token="t" />);
    expect(await screen.findByRole('button', { name: '移出历史 aaaaaaaa' })).toBeDisabled();
  });

  it('downloads source-free reports through the client', async () => {
    render(<Workspace token="t" />);
    fireEvent.click(await screen.findByRole('button', { name: '导出 Markdown aaaaaaaa' }));
    await waitFor(() => expect(downloadReport).toHaveBeenCalledWith('t', ID, 'markdown'));
    fireEvent.click(screen.getByRole('button', { name: '导出 JSON aaaaaaaa' }));
    await waitFor(() => expect(downloadReport).toHaveBeenCalledWith('t', ID, 'json'));
  });

  it('drops the session on 401 instead of retrying', async () => {
    const lost = vi.fn();
    vi.mocked(getOverview).mockRejectedValue(new ApiError('访问令牌无效或缺失。', undefined, 401));
    vi.mocked(getHistory).mockRejectedValue(new ApiError('访问令牌无效或缺失。', undefined, 401));
    render(<Workspace token="t" onAuthLost={lost} />);
    expect(await screen.findByText('会话已失效，请重新连接服务后再查看总览与历史。')).toBeInTheDocument();
    expect(lost).toHaveBeenCalled();
    await act(() => wait(300));
    expect(getHistory).toHaveBeenCalledTimes(1);
    expect(screen.queryByText('app.py')).not.toBeInTheDocument();
  });

  it('ignores a history response that was superseded by a newer filter', async () => {
    const slow = deferred<{ scans: HistoryRow[]; total: number }>();
    vi.mocked(getHistory).mockResolvedValueOnce({ scans: [row()], total: 1 }).mockReturnValueOnce(slow.promise)
      .mockResolvedValue({ scans: [row({ id: 'bbbbbbbb-0000-0000-0000-000000000002', status: 'failed' })], total: 1 });
    render(<Workspace token="t" />);
    await screen.findByRole('button', { name: '查看任务 aaaaaaaa' });
    fireEvent.change(screen.getByLabelText('历史状态'), { target: { value: 'completed' } }); // slow
    fireEvent.change(screen.getByLabelText('历史状态'), { target: { value: 'failed' } }); // fast
    await screen.findByRole('button', { name: '查看任务 bbbbbbbb' });
    await act(async () => { slow.resolve({ scans: [row()], total: 1 }); await wait(0); });
    expect(screen.queryByRole('button', { name: '查看任务 aaaaaaaa' })).not.toBeInTheDocument();
    expect(vi.mocked(getHistory).mock.calls.at(-1)?.[1]).toMatchObject({ status: 'failed' });
  });

  it('refreshes by itself when a scan is created or finishes', async () => {
    render(<Workspace token="t" />);
    await screen.findByRole('button', { name: '查看任务 aaaaaaaa' });
    const before = vi.mocked(getHistory).mock.calls.length;
    act(() => { window.dispatchEvent(new Event('aegisforge:changed')); });
    await waitFor(() => expect(vi.mocked(getHistory).mock.calls.length).toBe(before + 1));
    expect(getOverview).toHaveBeenCalledTimes(2);
  });
});

describe('scan panel after a removal, expiry or filter', () => {
  const render_ = (props: Partial<Parameters<typeof ScanPanel>[0]> = {}) =>
    render(<ScanPanel token="t" aliases={['fake']} artifacts={[]} onRemove={() => {}} {...props} />);

  it('clears the selection and the address when the task is removed elsewhere', async () => {
    window.history.replaceState(null, '', '/?scan=s1&repair=r1');
    vi.mocked(getScan).mockResolvedValue({ scan });
    render_();
    await screen.findByLabelText('任务详情');
    act(() => { window.dispatchEvent(new CustomEvent('aegisforge:deleted', { detail: { scanId: 's1' } })); });
    expect(await screen.findByText('该检测任务已移出历史，当前选择已清除。')).toBeInTheDocument();
    expect(screen.queryByLabelText('任务详情')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('候选修复详情')).not.toBeInTheDocument();
    expect(location.search).toBe('');
  });

  it('ignores a removal event for another task', async () => {
    window.history.replaceState(null, '', '/?scan=s1');
    vi.mocked(getScan).mockResolvedValue({ scan });
    render_();
    await screen.findByLabelText('任务详情');
    act(() => { window.dispatchEvent(new CustomEvent('aegisforge:deleted', { detail: { scanId: 'other' } })); });
    expect(screen.getByLabelText('任务详情')).toBeInTheDocument();
    expect(location.search).toBe('?scan=s1');
  });

  it('stops polling and forgets the task on 404', async () => {
    window.history.replaceState(null, '', '/?scan=s1&repair=r1');
    vi.mocked(getScan).mockRejectedValue(new ApiError('检测任务不存在。', undefined, 404));
    render_();
    expect(await screen.findByText('该检测任务已不在历史中，已清除当前选择。')).toBeInTheDocument();
    await act(() => wait(1800));
    expect(getScan).toHaveBeenCalledTimes(1);
    expect(location.search).toBe('');
  });

  it('clears task data and lets the owner drop the session once on 401', async () => {
    window.history.replaceState(null, '', '/?scan=s1');
    const lost = vi.fn();
    // A running task keeps being polled; the second poll finds the session expired.
    vi.mocked(getScan).mockResolvedValueOnce({ scan: { ...scan, status: 'running' } })
      .mockRejectedValue(new ApiError('访问令牌无效或缺失。', undefined, 401));
    render_({ onAuthLost: lost });
    await screen.findByLabelText('任务详情');
    await waitFor(() => expect(lost).toHaveBeenCalledTimes(1), { timeout: 3500 });
    expect(screen.queryByLabelText('任务详情')).not.toBeInTheDocument();
    expect(screen.getByText('会话已失效，请重新连接服务后再查看任务。')).toBeInTheDocument();
    await act(() => wait(1800));
    expect(getScan).toHaveBeenCalledTimes(2);
    expect(location.search).toBe('?scan=s1'); // kept so the task can be restored after reconnecting
  }, 10000);

  it('filters on the server, offers facet counts and ignores a superseded page', async () => {
    window.history.replaceState(null, '', '/?scan=s1');
    vi.mocked(getScan).mockResolvedValue({ scan });
    const slow = deferred<typeof page>();
    vi.mocked(getFindings).mockResolvedValueOnce(page)
      .mockReturnValueOnce(slow.promise)
      .mockResolvedValue(page);
    render_();
    const filter = await screen.findByLabelText('按 CWE 筛选');
    expect(within(filter).getByRole('option', { name: 'CWE-89（1）' })).toBeInTheDocument();
    fireEvent.change(filter, { target: { value: 'CWE-89' } }); // slow response
    await waitFor(() => expect(getFindings).toHaveBeenCalledTimes(2));
    expect(vi.mocked(getFindings).mock.calls[1].slice(2, 4)).toEqual([0, { cwe: 'CWE-89' }]);
    fireEvent.click(screen.getByRole('button', { name: '清除筛选' }));
    await waitFor(() => expect(getFindings).toHaveBeenCalledTimes(3));
    await act(async () => { slow.resolve({ ...page, findings: [page.findings[1]], total: 1 }); await wait(0); });
    expect(screen.getAllByText('CWE-78', { selector: '.ant-tag' }).length).toBeGreaterThan(0); // not replaced by the stale page
    expect(screen.getByText(/发现 2 项/)).toBeInTheDocument();
  });

  it('opens the evidence navigator on plain text and moves between findings with the keyboard', async () => {
    window.history.replaceState(null, '', '/?scan=s1');
    vi.mocked(getScan).mockResolvedValue({ scan });
    vi.mocked(getInput).mockResolvedValue({ input });
    const { container } = render_();
    fireEvent.click((await screen.findAllByRole('button', { name: '查看证据位置' }))[0]);
    const region = await screen.findByRole('group', { name: '源码与发现位置：app.py' });
    expect(getInput).toHaveBeenCalledWith('t', 's1', 'a1', expect.any(AbortSignal));
    expect(container.querySelector('.source-lines script')).toBeNull();
    expect(within(region).getByText("x = '<script>alert(1)</script>'")).toBeInTheDocument();
    expect(within(region).getByText('当前所选发现 · CWE-78')).toBeInTheDocument();
    expect(within(region).getByText('检测发现 · CWE-89')).toBeInTheDocument();
    fireEvent.keyDown(region, { key: 'n' });
    fireEvent.keyDown(region, { key: 'Enter' }); // opens the finding marked on that line
    expect(await screen.findByText('2 / 2')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '上一条发现' }));
    expect(screen.getByText('1 / 2')).toBeInTheDocument();
    expect(getInput).toHaveBeenCalledTimes(1); // the input is cached per task and artifact
  });

  it('forgets a task whose evidence can no longer be read', async () => {
    window.history.replaceState(null, '', '/?scan=s1');
    vi.mocked(getScan).mockResolvedValue({ scan });
    vi.mocked(getInput).mockRejectedValue(new ApiError('该检测任务没有这个输入快照。', undefined, 404));
    render_();
    fireEvent.click((await screen.findAllByRole('button', { name: '查看证据位置' }))[0]);
    expect(await screen.findByText('该检测任务已不在历史中，已清除当前选择。')).toBeInTheDocument();
    expect(location.search).toBe('');
  });

  it('lists every repair of the task, failed ones included, and reopens a selected one', async () => {
    window.history.replaceState(null, '', '/?scan=s1');
    vi.mocked(getScan).mockResolvedValue({ scan });
    vi.mocked(listRepairs).mockResolvedValue({ repairs: [
      repair({ id: 'rrrrrrrr-1', status: 'failed', error_code: 'PATCH_SCOPE' }),
      repair({ id: 'ssssssss-2', simulated: true, model_alias: 'fake' }),
    ] });
    render_();
    expect(await screen.findByLabelText('本任务的修复记录')).toBeInTheDocument();
    expect(screen.getByText('PATCH_SCOPE')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '打开修复记录 ssssssss' }));
    expect(new URLSearchParams(location.search).get('repair')).toBe('ssssssss-2');
    expect(screen.getByRole('button', { name: '打开修复记录 ssssssss' })).toHaveAttribute('aria-pressed', 'true');
  });
});

describe('repair panel removal and compare', () => {
  it('stops polling and notifies the owner when the repair is gone', async () => {
    const gone = vi.fn();
    vi.mocked(getRepair).mockRejectedValue(new ApiError('修复不存在。', undefined, 404));
    render(<RepairPanel token="t" id="r1" onGone={gone} />);
    await waitFor(() => expect(gone).toHaveBeenCalledTimes(1));
    await act(() => wait(1800));
    expect(getRepair).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/该候选修复已不存在/)).toBeInTheDocument();
  });

  it('notifies the owner about an expired session without polling again', async () => {
    const lost = vi.fn();
    vi.mocked(getRepair).mockRejectedValue(new ApiError('访问令牌无效或缺失。', undefined, 401));
    render(<RepairPanel token="t" id="r1" onAuthLost={lost} />);
    await waitFor(() => expect(lost).toHaveBeenCalledTimes(1));
    await act(() => wait(1800));
    expect(getRepair).toHaveBeenCalledTimes(1);
  });

  it('explains the candidate and compares both sides with persisting, introduced and changed lines', async () => {
    vi.mocked(getRepair).mockResolvedValue({ repair: repair() });
    vi.mocked(getCompare).mockResolvedValue({ compare });
    render(<RepairPanel token="t" id="r1" />);
    const card = await screen.findByLabelText('修复说明卡');
    expect(within(card).getByText(/不证明候选没有其他漏洞/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '对比原文与候选' }));
    const original = await screen.findByRole('group', { name: '原文源码' });
    const candidate = screen.getByRole('group', { name: '候选源码' });
    expect(within(original).getByText('修复目标 · CWE-78')).toBeInTheDocument();
    expect(within(candidate).getByText('新增风险 · CWE-89')).toBeInTheDocument();
    expect(within(candidate).getAllByText('改动').length).toBeGreaterThan(0);
    expect(screen.getByText(/新增风险 1/)).toBeInTheDocument();
    expect(getCompare).toHaveBeenCalledWith('t', 'r1', expect.any(AbortSignal));
  });

  it('shows why a comparison is unavailable instead of an empty pane', async () => {
    vi.mocked(getRepair).mockResolvedValue({ repair: repair() });
    vi.mocked(getCompare).mockRejectedValue(new ApiError('候选尚未生成或已失效。', undefined, 409));
    render(<RepairPanel token="t" id="r1" />);
    fireEvent.click(await screen.findByRole('button', { name: '对比原文与候选' }));
    expect(await screen.findByText('候选尚未生成或已失效。')).toBeInTheDocument();
    expect(screen.queryByRole('group', { name: '原文源码' })).not.toBeInTheDocument();
  });
});
