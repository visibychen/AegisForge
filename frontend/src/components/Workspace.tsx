import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Alert, Button, Input, Tag } from 'antd';
import {
  HISTORY_PAGE, deleteScan, downloadReport, getHistory, getOverview, isAborted, isAuthFailure, isGone,
} from '../api/client';
import type { HistoryFilters, HistoryRow, Overview } from '../types/api';

const RECONNECT = '会话已失效，请重新连接服务后再查看总览与历史。';
const STATUS: Record<string, string> = {
  queued: '排队中', running: '分析中', completed: '完成', partial: '部分完成', failed: '失败', cancelled: '已取消',
};
const MODE: Record<string, string> = { rules: '仅规则', simulated: '模拟模型（未做真实分析）', real: '真实模型' };
const VERDICT: Record<string, string> = { passed: '受控验证通过', failed: '验证未通过', error: '验证异常', unverified: '待验证' };
const REPAIR_STATUS: Record<string, string> = { queued: '排队中', running: '生成中', candidate: '候选已生成', failed: '失败', cancelled: '已取消' };
const DYNAMIC: Record<string, string> = { none: '未请求动态验证', pending: '等待验证', running: '验证中', passed: '固定测试通过', failed: '固定测试失败', error: '验证异常', cancelled: '已取消' };
const CWES = ['CWE-79', 'CWE-89', 'CWE-78'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

function Chips({ data, labels }: { data: Record<string, number>; labels?: Record<string, string> }) {
  const entries = Object.entries(data);
  if (entries.length === 0) return <span className="repair-impact">暂无</span>;
  return <>{entries.map(([key, count]) => <Tag key={key}>{labels?.[key] ?? key} {count}</Tag>)}</>;
}

function Metric({ title, children }: { title: string; children: ReactNode }) {
  return <div className="metric"><h3>{title}</h3><div>{children}</div></div>;
}

function completeness(row: HistoryRow): string {
  if (row.mode === 'rules') return '仅规则，未做模型分析';
  if (row.analysis_complete === true) return '分析完整';
  if (row.analysis_complete === false) return '分析不完整';
  return '分析进度未记录';
}

export default function Workspace({ token, onAuthLost }: {
  token: string;
  /** Called once when a request proves the session is unusable, so the owner can drop the token. */
  onAuthLost?: () => void;
}) {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [rows, setRows] = useState<HistoryRow[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [filters, setFilters] = useState<HistoryFilters>({ status: 'all' });
  const [typed, setTyped] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(false);
  const [pending, setPending] = useState('');
  const [working, setWorking] = useState('');
  const filtersRef = useRef(filters);
  filtersRef.current = filters;

  function authLost() {
    setOverview(null); setRows([]); setTotal(0); setPending('');
    setError(RECONNECT);
    onAuthLost?.();
  }

  // Auto-refresh after scans are created/finished and repairs change (see ScanPanel).
  useEffect(() => {
    const changed = () => setRevision(v => v + 1);
    window.addEventListener('aegisforge:changed', changed);
    return () => window.removeEventListener('aegisforge:changed', changed);
  }, []);

  useEffect(() => {
    // Typing is debounced; the server query only changes once the text settles.
    const timer = setTimeout(() => {
      if ((filtersRef.current.q ?? '') === typed) return;
      setFilters({ ...filtersRef.current, q: typed || undefined }); setOffset(0);
    }, 250);
    return () => clearTimeout(timer);
  }, [typed]);

  useEffect(() => {
    if (!token) { setOverview(null); setRows([]); setTotal(0); setError(''); setNotice(''); setPending(''); return; }
    const controller = new AbortController();
    getOverview(token, controller.signal)
      .then(data => { if (!controller.signal.aborted) { setOverview(data); setError(''); } })
      .catch(e => {
        if (isAborted(e) || controller.signal.aborted) return;
        if (isAuthFailure(e)) authLost(); else setError(e instanceof Error ? e.message : '总览读取失败。');
      });
    return () => controller.abort();
  }, [token, revision]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!token) { setLoading(false); return; }
    const controller = new AbortController();
    setLoading(true);
    getHistory(token, filters, offset, controller.signal)
      .then(data => {
        if (controller.signal.aborted) return; // a newer page/filter superseded this response
        setRows(data.scans); setTotal(data.total); setError('');
        if (data.scans.length === 0 && offset > 0 && data.total > 0) setOffset(Math.max(0, offset - HISTORY_PAGE));
      })
      .catch(e => {
        if (isAborted(e) || controller.signal.aborted) return;
        if (isAuthFailure(e)) authLost(); else setError(e instanceof Error ? e.message : '历史读取失败。');
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [token, offset, filters, revision]); // eslint-disable-line react-hooks/exhaustive-deps

  async function remove(id: string) {
    setWorking(`delete:${id}`); setError(''); setNotice('');
    try {
      const result = await deleteScan(token, id);
      setNotice(`已移出历史。${result.retained}`);
      afterRemoval(id);
    } catch (e) {
      if (isGone(e)) { setNotice('该任务已不在历史中。'); afterRemoval(id); }
      else if (isAuthFailure(e)) authLost();
      else setError(e instanceof Error ? e.message : '移出历史失败。');
    } finally { setWorking(''); setPending(''); }
  }
  /** Tell the rest of the page, forget the id in the address bar, and refresh both lists. */
  function afterRemoval(id: string) {
    const url = new URL(location.href);
    if (url.searchParams.get('scan') === id) {
      url.searchParams.delete('scan'); url.searchParams.delete('repair');
      window.history.replaceState(null, '', url);
    }
    window.dispatchEvent(new CustomEvent('aegisforge:deleted', { detail: { scanId: id } }));
    setRevision(v => v + 1); // an emptied last page steps back when the history reloads
  }
  async function download(id: string, format: 'json' | 'markdown') {
    setWorking(`${format}:${id}`); setError('');
    try { await downloadReport(token, id, format); }
    catch (e) {
      if (isGone(e)) { setNotice('该任务已不在历史中。'); setRevision(v => v + 1); }
      else if (isAuthFailure(e)) authLost();
      else setError(e instanceof Error ? e.message : '报告导出失败。');
    } finally { setWorking(''); }
  }
  function open(id: string) {
    const url = new URL(location.href);
    url.searchParams.set('scan', id); url.searchParams.delete('repair');
    window.history.replaceState(null, '', url);
    window.dispatchEvent(new Event('aegisforge:scan'));
    document.getElementById('scans')?.scrollIntoView?.({ behavior: 'instant' });
  }
  const setFilter = (key: keyof HistoryFilters, value: string) => { setFilters(f => ({ ...f, [key]: value || undefined })); setOffset(0); };
  const narrowed = Boolean(filters.q || filters.cwe || filters.severity || (filters.status && filters.status !== 'all'));

  return <>
    <section className="surface" id="overview" aria-label="任务总览"><h2>任务总览</h2>
      <p>当前尝试的静态风险计数，不是确认漏洞数或准确率；模拟与仅规则结果不是真实模型分析。</p>
      {!token && <p>连接服务后查看总览与历史。</p>}
      {token && !overview && !error && <p role="status">正在读取总览…</p>}
      {overview && (overview.tasks === 0 ? <p>还没有检测任务。保存输入快照并创建任务后，这里会显示计数。</p> : <div className="workspace-metrics">
        <Metric title="任务数"><strong className="metric-number">{overview.tasks}</strong></Metric>
        <Metric title="任务状态"><Chips data={overview.states} labels={STATUS} /></Metric>
        <Metric title="分析模式"><Chips data={overview.modes} labels={MODE} />
          {overview.modes.real ? <p className="repair-impact">真实模型任务结果：<Chips data={overview.real_outcomes} labels={STATUS} /></p> : null}</Metric>
        <Metric title="漏洞类型（候选风险）"><Chips data={overview.cwes} /></Metric>
        <Metric title="风险等级"><Chips data={overview.severities} /></Metric>
        <Metric title="候选修复">
          <p><strong className="metric-number">{overview.repairs.total}</strong> 个，其中模拟 {overview.repairs.simulated}</p>
          <Chips data={overview.repairs.by_status} labels={REPAIR_STATUS} />
          <p className="repair-impact">验证结论：<Chips data={overview.repairs.verdicts} labels={VERDICT} />（当前尝试最近 {overview.repairs.verdict_sampled ?? 0} / 共 {overview.repairs.candidates_total ?? 0} 个候选，上限 {overview.repairs.verdict_limit ?? 300}；归档 {overview.repairs.archived ?? 0} 个）</p>
          <p className="repair-impact">动态验证：<Chips data={overview.repairs.dynamic} labels={DYNAMIC} /></p>
        </Metric>
      </div>)}
    </section>
    <section className="surface" id="history" aria-label="历史管理"><h2>历史管理与报告</h2>
      <p>JSON/Markdown 报告默认不含源码、文件名、HTTP 参数名或模型自由文本，摘要是完整性记录而不是数字签名。移出历史只是停止访问该任务；预算审计保留，输入快照仍可按编号预览，不是文件擦除。</p>
      <div className="ingest-actions history-filters">
        <Input aria-label="按任务编号查询" value={typed} maxLength={64} placeholder="按任务编号查询" onChange={e => setTyped(e.target.value)} />
        <select aria-label="历史状态" value={filters.status ?? 'all'} onChange={e => setFilter('status', e.target.value)}>
          <option value="all">全部状态</option>
          {Object.entries(STATUS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
        <select aria-label="历史漏洞类型" value={filters.cwe ?? ''} onChange={e => setFilter('cwe', e.target.value)}>
          <option value="">全部类型</option>{CWES.map(value => <option key={value} value={value}>{value}</option>)}
        </select>
        <select aria-label="历史风险等级" value={filters.severity ?? ''} onChange={e => setFilter('severity', e.target.value)}>
          <option value="">全部等级</option>{SEVERITIES.map(value => <option key={value} value={value}>{value}</option>)}
        </select>
        <Button disabled={!token || loading} onClick={() => setRevision(v => v + 1)}>刷新总览与历史</Button></div>
      {notice && <Alert type="success" title={notice} role="status" closable={{ onClose: () => setNotice('') }} />}
      {error && <Alert type="error" title={error} role="alert" />}
      {loading && <p role="status">正在读取历史…</p>}
      {token && !loading && !error && rows.length === 0 && <p>{narrowed ? '没有匹配的历史任务，请调整筛选条件。' : '历史为空：创建检测任务后会出现在这里。'}</p>}
      <ul className="history-list">{rows.map(row => {
        const short = row.id.slice(0, 8);
        const confirming = pending === row.id;
        return <li key={row.id} className="history-row">
          <div className="history-head"><Tag>{STATUS[row.status] ?? row.status}</Tag><Tag>{MODE[row.mode] ?? row.mode}</Tag><Tag>{completeness(row)}</Tag><code>{row.id}</code></div>
          <p className="repair-impact">{row.artifacts.length > 0 ? row.artifacts.map(a => a.display_name).join('、') : '无输入记录'} · 第 {row.attempt + 1} 次尝试{row.error_code ? ` · ${row.error_code}` : ''}</p>
          <p>候选风险 {row.findings.total} 项 <Chips data={row.findings.cwes} /> <Chips data={row.findings.severities} />
            · 修复记录 {row.repairs.total}（当前 {row.repairs.current ?? row.repairs.total}，归档 {row.repairs.archived ?? 0}，模拟 {row.repairs.simulated}）</p>
          <div className="ingest-actions">
            <Button aria-label={`查看任务 ${short}`} onClick={() => open(row.id)}>查看任务</Button>
            <Button aria-label={`导出 JSON ${short}`} loading={working === `json:${row.id}`} onClick={() => void download(row.id, 'json')}>导出 JSON</Button>
            <Button aria-label={`导出 Markdown ${short}`} loading={working === `markdown:${row.id}`} onClick={() => void download(row.id, 'markdown')}>导出 Markdown</Button>
            <Button danger aria-label={`移出历史 ${short}`} disabled={Boolean(working) || ['queued', 'running'].includes(row.status)} onClick={() => setPending(row.id)}>移出历史</Button>
            {confirming && <><span role="alert">确认移出该任务？预算审计和输入快照仍保留，此操作不会擦除文件。</span>
              <Button danger loading={working === `delete:${row.id}`} onClick={() => void remove(row.id)}>确认移出</Button>
              <Button aria-label="保留" onClick={() => setPending('')}>保留</Button></>}
          </div></li>;
      })}</ul>
      <div className="ingest-actions"><Button disabled={offset === 0 || loading} onClick={() => setOffset(Math.max(0, offset - HISTORY_PAGE))}>上一页历史</Button><span>{total} 项 · 第 {Math.floor(offset / HISTORY_PAGE) + 1} 页</span><Button disabled={offset + HISTORY_PAGE >= total || loading} onClick={() => setOffset(offset + HISTORY_PAGE)}>下一页历史</Button></div>
    </section>
  </>;
}
