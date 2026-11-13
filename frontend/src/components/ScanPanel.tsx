import { useEffect, useRef, useState } from 'react';
import { Alert, Button, ConfigProvider, Select, Tag } from 'antd';
import {
  FINDING_PAGE, changeScan, createRepair, createScan, getFindings, getScan, isAborted, isAuthFailure, isGone, listRepairs,
} from '../api/client';
import type { ArtifactPreview, FindingFacets, FindingFilters, Repair, Scan, StoredFinding, Strategy } from '../types/api';
import CoverageLedger from './CoverageLedger';
import AnalysisReceipt from './AnalysisReceipt';
import StaticProofs from './StaticProofs';
import EvidenceViewer from './EvidenceViewer';
import RepairPanel from './RepairPanel';

const RECONNECT = '会话已失效，请重新连接服务后再查看任务。';
const SCAN_GONE = '该检测任务已不在历史中，已清除当前选择。';
const REPAIR_GONE = '该候选修复已不存在，已清除当前选择。';

const STATUS = { queued: '排队中', running: '分析中', completed: '完成', partial: '部分完成', failed: '失败', cancelled: '已取消' };
const TERMINAL = new Set(['completed', 'partial', 'failed', 'cancelled']);
const REPAIR_STATUS: Record<string, string> = { queued: '排队中', running: '生成中', candidate: '候选已生成', failed: '失败', cancelled: '已取消' };
const FILTERS: { key: keyof FindingFilters; label: string; facet: keyof FindingFacets }[] = [
  { key: 'cwe', label: '按 CWE 筛选', facet: 'cwe' },
  { key: 'severity', label: '按等级筛选', facet: 'severity' },
  { key: 'source', label: '按来源筛选', facet: 'source' },
  { key: 'evidence_status', label: '按证据状态筛选', facet: 'evidence_status' },
];
const CHANGED = 'aegisforge:changed';

function syncUrl(next: { scan?: string; repair?: string }) {
  const url = new URL(location.href);
  for (const [key, value] of Object.entries(next)) {
    if (value) url.searchParams.set(key, value); else url.searchParams.delete(key);
  }
  window.history.replaceState(null, '', url);
}
const announceChange = () => window.dispatchEvent(new Event(CHANGED));

export default function ScanPanel({token, aliases, artifacts, onRemove, onAuthLost}: {
  token: string; aliases: string[]; artifacts: ArtifactPreview[]; onRemove: (id: string) => void;
  /** Called once when a request proves the session is unusable, so the owner can drop the token. */
  onAuthLost?: () => void;
}) {
  const [strategy, setStrategy] = useState<Strategy>('hybrid');
  const [alias, setAlias] = useState(aliases.includes('deepseek') ? 'deepseek' : 'fake');
  const [id, setId] = useState(() => new URLSearchParams(location.search).get('scan') ?? '');
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<StoredFinding[]>([]);
  const [findingTotal, setFindingTotal] = useState(0);
  const [facets, setFacets] = useState<FindingFacets | null>(null);
  const [filters, setFilters] = useState<FindingFilters>({});
  const [offset, setOffset] = useState(0);
  const [evidenceId, setEvidenceId] = useState('');
  const [repairs, setRepairs] = useState<Repair[]>([]);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [repairRevision, setRepairRevision] = useState(0);
  const [repairId, setRepairId] = useState(() => new URLSearchParams(location.search).get('repair') ?? '');
  // A repair request keeps one idempotency key until it succeeds, so a lost response or a
  // double click can never create (and pay for) a second candidate.
  const repairSubmission = useRef<{ signature: string; key: string } | null>(null);
  function showRepair(next: string) {
    setRepairId(next);
    syncUrl({ repair: next });
  }
  /** Forget the selected task and repair everywhere (state and address bar) and say why. */
  function clearSelection(message: string) {
    setId(''); setRepairId(''); setScan(null); setFindings([]); setFindingTotal(0); setFacets(null); setRepairs([]);
    setEvidenceId(''); setFilters({}); setOffset(0); setError(''); setNotice(message);
    syncUrl({ scan: '', repair: '' });
  }
  function authLost() {
    setScan(null); setFindings([]); setFindingTotal(0); setFacets(null); setRepairs([]); setEvidenceId('');
    setError(RECONNECT);
    onAuthLost?.();
  }
  async function repairFinding(finding: StoredFinding) {
    const source = scan?.artifacts.find(a => a.id === finding.location.artifact_id);
    if (!source || busy) return;
    setBusy(true); setError(''); setNotice('');
    const signature = `${finding.id}|${source.sha256}|${alias}`;
    const current = repairSubmission.current?.signature === signature ? repairSubmission.current : { signature, key: crypto.randomUUID() };
    repairSubmission.current = current;
    try {
      const data = await createRepair(token, finding.id, source.sha256, alias, current.key);
      repairSubmission.current = null;
      showRepair(data.repair.id);
      announceChange();
    } catch (e) {
      if (isGone(e)) clearSelection(SCAN_GONE);
      else if (isAuthFailure(e)) authLost();
      else setError(e instanceof Error ? e.message : '修复创建失败。');
    }
    finally { setBusy(false); }
  }
  // One idempotency key per submission intent: reused on resubmit until it succeeds or the
  // inputs/strategy/model change, so a lost response cannot create a duplicate task.
  const submission = useRef<{ signature: string; key: string } | null>(null);
  useEffect(() => { setAlias(aliases.includes('deepseek') ? 'deepseek' : 'fake'); }, [aliases.join(',')]);

  function selectScan(next: string) {
    if (next !== id) { showRepair(''); setFilters({}); setEvidenceId(''); setNotice(''); } // a repair belongs to one scan
    setId(next); setOffset(0);
    syncUrl({ scan: next, ...(next !== id ? { repair: '' } : {}) });
  }

  // Poll the task until it is terminal. The server is the only source of truth for its state.
  useEffect(() => {
    let live = true;
    const controller = new AbortController();
    setScan(null); setError('');
    if (!token || !id) return;
    let running = false;
    let stopped = false;
    const poll = async () => {
      if (running || stopped) return;
      running = true;
      try {
        const data = await getScan(token, id, controller.signal);
        if (!live) return;
        setScan(data.scan); setError('');
        if (TERMINAL.has(data.scan.status)) { stopped = true; clearInterval(timer); announceChange(); }
      } catch (e) {
        if (!live || isAborted(e)) return;
        if (isGone(e)) { stopped = true; clearInterval(timer); clearSelection(SCAN_GONE); return; }
        if (isAuthFailure(e)) { stopped = true; clearInterval(timer); authLost(); return; }
        setError(e instanceof Error ? e.message : '任务查询失败。');
      }
      finally { running = false; }
    };
    const timer = setInterval(() => void poll(), 1500);
    void poll();
    return () => { live = false; controller.abort(); clearInterval(timer); };
  }, [token, id, refresh]); // eslint-disable-line react-hooks/exhaustive-deps

  // Findings of the current attempt: filtered and paged on the server.
  const settled = scan && TERMINAL.has(scan.status) ? `${scan.id}|${scan.status}|${scan.retries}` : '';
  useEffect(() => {
    if (!token || !settled || !scan) { setFindings([]); setFindingTotal(0); setFacets(null); return; }
    const controller = new AbortController();
    getFindings(token, scan.id, offset, filters, controller.signal)
      .then(result => {
        if (controller.signal.aborted) return; // a newer page/filter/task superseded this response
        setFindings(result.findings); setFindingTotal(result.total); setFacets(result.facets ?? null);
      })
      .catch(e => {
        if (isAborted(e) || controller.signal.aborted) return; // a newer page/filter/task superseded this one
        if (isGone(e)) clearSelection(SCAN_GONE);
        else if (isAuthFailure(e)) authLost();
        else setError(e instanceof Error ? e.message : '发现列表读取失败。');
      });
    return () => controller.abort();
  }, [token, settled, offset, filters, refresh]); // eslint-disable-line react-hooks/exhaustive-deps

  // Repair history of this task (failed candidates stay listed so they can be inspected).
  useEffect(() => {
    if (!token || !scan) { setRepairs([]); return; }
    const controller = new AbortController();
    listRepairs(token, scan.id, controller.signal)
      .then(result => { if (!controller.signal.aborted) setRepairs(result.repairs); })
      .catch(e => {
        if (isAborted(e) || controller.signal.aborted) return;
        if (isGone(e)) clearSelection(SCAN_GONE);
        else if (isAuthFailure(e)) authLost();
        // Any other failure only hides this convenience list; the task itself stays usable.
      });
    return () => controller.abort();
  }, [token, scan?.id, scan?.status, repairId, repairRevision]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const restore = () => { selectScan(new URLSearchParams(location.search).get('scan') ?? ''); setRefresh(v => v + 1); };
    const removed = (event: Event) => {
      const removedId = (event as CustomEvent<{ scanId?: string }>).detail?.scanId;
      if (removedId && removedId === id) clearSelection('该检测任务已移出历史，当前选择已清除。');
    };
    window.addEventListener('aegisforge:scan', restore);
    window.addEventListener('aegisforge:deleted', removed);
    return () => { window.removeEventListener('aegisforge:scan', restore); window.removeEventListener('aegisforge:deleted', removed); };
  }, [id]); // eslint-disable-line react-hooks/exhaustive-deps

  async function submit() {
    setBusy(true); setError(''); setNotice('');
    const ids = artifacts.map(a => a.id);
    const signature = JSON.stringify([[...ids].sort(), strategy, alias]);
    const current = submission.current?.signature === signature ? submission.current : { signature, key: crypto.randomUUID() };
    submission.current = current;
    try {
      const result = await createScan(token, ids, strategy, alias, current.key);
      submission.current = null;
      selectScan(result.scan.id); setRefresh(value => value + 1); announceChange();
    } catch (e) {
      if (isAuthFailure(e)) authLost(); else setError(e instanceof Error ? e.message : '任务创建失败。');
    }
    finally { setBusy(false); }
  }
  async function action(kind: 'cancel' | 'retry') {
    setBusy(true); setError('');
    try { await changeScan(token, id, kind); setRefresh(value => value + 1); announceChange(); }
    catch (e) {
      if (isGone(e)) clearSelection(SCAN_GONE);
      else if (isAuthFailure(e)) authLost();
      else setError(e instanceof Error ? e.message : '操作失败。');
    }
    finally { setBusy(false); }
  }
  function setFilter(key: keyof FindingFilters, value: string) {
    setFilters(current => ({ ...current, [key]: value || undefined }));
    setOffset(0); setEvidenceId('');
  }
  const filtered = Object.values(filters).some(Boolean);
  const nameOf = (artifactId: string) => scan?.artifacts.find(a => a.id === artifactId)?.display_name ?? artifactId;

  return <ConfigProvider wave={{disabled: true}}><section className="surface scan-panel" id="scans" aria-labelledby="scan-title">
    <div className="section-heading"><h2 id="scan-title">检测任务</h2><Tag>证据驱动</Tag></div>
    <p>先保存输入快照，再选择分析方式。任务刷新后可用地址恢复，访问令牌需重新连接。历史任务请在上方“历史管理与报告”中选择。</p>
    <div className="selected-artifacts">{artifacts.map(a => <div key={a.id}><span>{a.display_name}</span><Tag>{a.input_type}</Tag><Button size="small" onClick={() => onRemove(a.id)} aria-label={`移除 ${a.display_name}`}>移除</Button></div>)}</div>
    <div className="scan-controls">
      <div><label htmlFor="scan-strategy">分析方式</label><Select id="scan-strategy" aria-label="分析方式" value={strategy} onChange={setStrategy} options={[{value:'hybrid',label:'规则 + 模型'},{value:'rules',label:'仅规则'},{value:'llm',label:'仅模型'}]} /></div>
      <div><label htmlFor="scan-model">模型</label><Select id="scan-model" aria-label="模型" value={alias} onChange={setAlias} options={aliases.map(value => ({value,label:value === 'deepseek' ? 'DeepSeek' : '模拟模型'}))} /></div>
      <p>候选修复使用当前选择的模型；DeepSeek 会产生外部调用。仅规则检测不调用模型。</p>
      <Button type="primary" loading={busy} disabled={!token || artifacts.length === 0 || artifacts.length > 10} onClick={() => void submit()}>创建检测任务</Button>
    </div>
    {artifacts.length > 10 && <Alert type="warning" title="每个任务最多 10 个快照，请移除多余输入。" />}
    {strategy === 'rules' ? <p>规则模式不会调用模型；未命中不代表安全。</p> : alias === 'fake' ? <Alert type="warning" title="模拟模型不执行真实分析，任务会明确标为部分完成。" /> : <p>DeepSeek 分析会发送脱敏内容，并计入服务器的调用预算。</p>}
    {!token && <p>{id ? '重新连接服务后可恢复此检测任务。' : '连接服务后可创建或查看任务。'}</p>}
    {notice && <Alert type="info" title={notice} role="status" closable={{ onClose: () => setNotice('') }} />}
    {error && <Alert type="error" title={error} role="alert" />}
    {token && id && !scan && !error && <p role="status">正在读取任务…</p>}
    {scan && <article className="scan-detail" aria-label="任务详情">
      <h3><Tag color={scan.status === 'completed' ? 'success' : scan.status === 'failed' ? 'error' : 'processing'}>{STATUS[scan.status]}</Tag><code>{scan.id}</code></h3>
      <p>{scan.strategy} · {scan.model_alias} · 外部调用 {scan.call_count} 次 · 模型分块 {scan.result.completed_chunks ?? 0}/{scan.result.expected_chunks ?? 0}</p>
      {scan.budget && <p>调用预算：本任务 {scan.budget.scan_used}/{scan.budget.scan_limit} · 今日服务器 {scan.budget.daily_used}/{scan.budget.daily_limit}（次数，不是费用）</p>}
      {scan.result.coverage && scan.result.coverage.length > 0 && <CoverageLedger entries={scan.result.coverage} />}
      <AnalysisReceipt scan={scan} />
      <StaticProofs result={scan.result} />
      {scan.attempts && scan.attempts.length > 0 && <details><summary>此前尝试（{scan.attempts.length}）</summary><ul>{scan.attempts.map(item => <li key={item.attempt}>第 {item.attempt + 1} 次：{STATUS[item.status as keyof typeof STATUS] ?? item.status}{item.error_code ? ` · ${item.error_code}` : ''} · 发现 {item.summary.finding_count ?? 0} 项</li>)}</ul></details>}
      {scan.error_code && <Alert type="warning" title={`任务错误：${scan.error_code}`} />}
      {scan.result.warnings?.map((warning, index) => <Alert key={index} type="warning" title={warning} />)}
      {['queued','running'].includes(scan.status) && <Button disabled={busy || scan.cancel_requested} onClick={() => void action('cancel')}>{scan.cancel_requested ? '正在取消' : '取消任务'}</Button>}
      {['partial','failed','cancelled'].includes(scan.status) && <Button disabled={busy || scan.retries >= 2} onClick={() => void action('retry')}>按当前配置重试</Button>}
      <p>发现 {findingTotal} 项{filtered ? '（已筛选）' : ''}；结果为静态风险判断，运行时效果尚未验证。</p>
      {facets && Object.values(facets).some(group => Object.keys(group).length > 0) && <div className="finding-filters" role="group" aria-label="发现筛选">
        {FILTERS.map(({ key, label, facet }) => Object.keys(facets[facet]).length > 0 && <label key={key}>{label}
          <select value={filters[key] ?? ''} onChange={event => setFilter(key, event.target.value)}>
            <option value="">全部</option>
            {Object.entries(facets[facet]).map(([value, count]) => <option key={value} value={value}>{value}（{count}）</option>)}
          </select></label>)}
        {filtered && <Button size="small" onClick={() => { setFilters({}); setOffset(0); setEvidenceId(''); }}>清除筛选</Button>}
      </div>}
      {filtered && findings.length === 0 && TERMINAL.has(scan.status) && <p>没有符合筛选条件的发现。</p>}
      {findings.map(f => <div className="finding-card" key={f.id}>
        <h4><Tag>{f.cwe}</Tag><Tag>{f.severity}</Tag>{f.sources.join(' + ')} {f.severity_disagreement && <Tag color="warning">严重性判断有差异</Tag>}</h4>
        <p>{nameOf(f.location.artifact_id)} · {f.location.kind === 'source' ? `第 ${f.location.start_line}–${f.location.end_line} 行` : f.location.field} · {f.evidence_status}</p>
        <pre>{f.evidence}</pre><p>{f.explanation}</p><p>建议：{f.recommendation}</p>
        <details><summary>查看各来源判断</summary>{f.contributors.map((item,index) => <div key={index}><Tag>{item.sources.join(' + ')}</Tag><Tag>{item.severity}</Tag><p>{item.explanation}</p><p>{item.recommendation}</p></div>)}</details>
        <div className="ingest-actions">
          <Button aria-pressed={evidenceId === f.id} onClick={() => setEvidenceId(current => current === f.id ? '' : f.id)}>{evidenceId === f.id ? '收起证据位置' : '查看证据位置'}</Button>
          <Button disabled={busy || f.location.kind !== 'source'} onClick={() => void repairFinding(f)}>生成{alias === 'fake' ? '模拟' : 'DeepSeek'}候选修复</Button>
        </div>
      </div>)}
      {evidenceId && <EvidenceViewer token={token} scanId={scan.id} findings={findings} selectedId={evidenceId} onSelect={setEvidenceId}
        onGone={() => clearSelection(SCAN_GONE)} onAuthLost={authLost} />}
      {findingTotal > FINDING_PAGE && <div className="ingest-actions"><Button disabled={offset === 0} onClick={() => setOffset(Math.max(0,offset-FINDING_PAGE))}>上一页</Button><span>{offset+1}–{Math.min(offset+FINDING_PAGE,findingTotal)} / {findingTotal}</span><Button disabled={offset+FINDING_PAGE >= findingTotal} onClick={() => setOffset(offset+FINDING_PAGE)}>下一页</Button></div>}
      {repairs.length > 0 && <section className="repair-history" aria-label="本任务的修复记录">
        <h4>本任务的修复记录（{repairs.length}）</h4>
        <ul>{repairs.map(item => <li key={item.id}>
          <Button size="small" type={item.id === repairId ? 'primary' : 'default'} aria-pressed={item.id === repairId} aria-label={`打开修复记录 ${item.id.slice(0, 8)}`} onClick={() => showRepair(item.id)}>{item.id.slice(0, 8)}</Button>
          <Tag>{REPAIR_STATUS[item.status] ?? item.status}</Tag><Tag>{item.simulated ? '模拟' : item.model_alias}</Tag>
          {item.error_code && <code>{item.error_code}</code>}
          {item.created_at && <small>{new Date(item.created_at).toLocaleString()}</small>}
        </li>)}</ul>
      </section>}
    </article>}
    <RepairPanel token={token} id={repairId} scanId={scan?.id} scanAttempt={scan?.retries}
      onGone={() => { showRepair(''); setNotice(REPAIR_GONE); setRepairRevision(v => v + 1); }}
      onAuthLost={authLost} onChanged={() => { setRepairRevision(v => v + 1); announceChange(); }} />
  </section></ConfigProvider>;
}
