import { useEffect, useRef, useState } from 'react';
import { Alert, Button, ConfigProvider, Select, Tag } from 'antd';
import { changeScan, createScan, getFindings, getScan, isAuthFailure, listScans } from '../api/client';
import type { ArtifactPreview, Scan, StoredFinding, Strategy } from '../types/api';
import CoverageLedger from './CoverageLedger';
import AnalysisReceipt from './AnalysisReceipt';
import RepairPanel from './RepairPanel';
import { createRepair } from '../api/client';

const RECONNECT = '会话已失效，请重新连接服务后再查看任务。';

const STATUS = { queued: '排队中', running: '分析中', completed: '完成', partial: '部分完成', failed: '失败', cancelled: '已取消' };
const TERMINAL = new Set(['completed', 'partial', 'failed', 'cancelled']);

export default function ScanPanel({token, aliases, artifacts, onRemove}: {
  token: string; aliases: string[]; artifacts: ArtifactPreview[]; onRemove: (id: string) => void;
}) {
  const [strategy, setStrategy] = useState<Strategy>('hybrid');
  const [alias, setAlias] = useState(aliases.includes('deepseek') ? 'deepseek' : 'fake');
  const [id, setId] = useState(() => new URLSearchParams(location.search).get('scan') ?? '');
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<StoredFinding[]>([]);
  const [findingTotal, setFindingTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [history, setHistory] = useState<Scan[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [repairId, setRepairId] = useState(() => new URLSearchParams(location.search).get('repair') ?? '');
  async function repairFinding(finding: StoredFinding) {
    const source = scan?.artifacts.find(a => a.id === finding.location.artifact_id);
    if (!source) return;
    setBusy(true);
    try {
      const data = await createRepair(token, finding.id, source.sha256, alias, crypto.randomUUID());
      setRepairId(data.repair.id);
      const url = new URL(location.href); url.searchParams.set('repair',data.repair.id); window.history.replaceState(null,'',url);
    } catch (e) { setError(e instanceof Error ? e.message : '修复创建失败。'); }
    finally { setBusy(false); }
  }
  // One idempotency key per submission intent: reused on resubmit until it succeeds or the
  // inputs/strategy/model change, so a lost response cannot create a duplicate task.
  const submission = useRef<{ signature: string; key: string } | null>(null);
  useEffect(() => { setAlias(aliases.includes('deepseek') ? 'deepseek' : 'fake'); }, [aliases.join(',')]);

  function selectScan(next: string) {
    setId(next); setOffset(0);
    const url = new URL(location.href); url.searchParams.set('scan', next);
    window.history.replaceState(null, '', url);
  }

  useEffect(() => {
    let live = true;
    setScan(null); setFindings([]); setFindingTotal(0); setError('');
    if (!token) { setHistory([]); return; }
    listScans(token).then(data => { if (live) setHistory(data.scans); })
      .catch(e => { if (live) setError(isAuthFailure(e) ? RECONNECT : e instanceof Error ? e.message : '任务记录读取失败。'); });
    if (!id) return () => { live = false; };
    let running = false;
    let stopped = false;
    const poll = async () => {
      if (running || stopped) return;
      running = true;
      try {
        const data = await getScan(token, id);
        if (!live) return;
        setScan(data.scan); setError('');
        if (TERMINAL.has(data.scan.status)) {
          const result = await getFindings(token, id, offset);
          if (live) { setFindings(result.findings); setFindingTotal(result.total); }
          clearInterval(timer);
          const latest = await listScans(token);
          if (live) setHistory(latest.scans);
        }
      } catch (e) {
        if (isAuthFailure(e)) { stopped = true; clearInterval(timer); }
        if (live) setError(isAuthFailure(e) ? RECONNECT : e instanceof Error ? e.message : '任务查询失败。');
      }
      finally { running = false; }
    };
    const timer = setInterval(() => void poll(), 1500);
    void poll();
    return () => { live = false; clearInterval(timer); };
  }, [token, id, offset, refresh]);

  async function submit() {
    setBusy(true); setError('');
    const ids = artifacts.map(a => a.id);
    const signature = JSON.stringify([[...ids].sort(), strategy, alias]);
    const current = submission.current?.signature === signature ? submission.current : { signature, key: crypto.randomUUID() };
    submission.current = current;
    try {
      const result = await createScan(token, ids, strategy, alias, current.key);
      submission.current = null;
      selectScan(result.scan.id); setRefresh(value => value + 1);
    } catch (e) { setError(isAuthFailure(e) ? RECONNECT : e instanceof Error ? e.message : '任务创建失败。'); }
    finally { setBusy(false); }
  }
  async function action(kind: 'cancel' | 'retry') {
    setBusy(true); setError('');
    try { await changeScan(token, id, kind); setRefresh(value => value + 1); }
    catch (e) { setError(e instanceof Error ? e.message : '操作失败。'); }
    finally { setBusy(false); }
  }

  return <ConfigProvider wave={{disabled: true}}><section className="surface scan-panel" id="scans" aria-labelledby="scan-title">
    <div className="section-heading"><h2 id="scan-title">检测任务</h2><Tag>证据驱动</Tag></div>
    <p>先保存输入快照，再选择分析方式。任务刷新后可用地址恢复，访问令牌需重新连接。</p>
    <div className="selected-artifacts">{artifacts.map(a => <div key={a.id}><span>{a.display_name}</span><Tag>{a.input_type}</Tag><Button size="small" onClick={() => onRemove(a.id)} aria-label={`移除 ${a.display_name}`}>移除</Button></div>)}</div>
    <div className="scan-controls">
      <div><label htmlFor="scan-strategy">分析方式</label><Select id="scan-strategy" aria-label="分析方式" value={strategy} onChange={setStrategy} options={[{value:'hybrid',label:'规则 + 模型'},{value:'rules',label:'仅规则'},{value:'llm',label:'仅模型'}]} /></div>
      <div><label htmlFor="scan-model">模型</label><Select id="scan-model" aria-label="模型" value={alias} onChange={setAlias} disabled={strategy === 'rules'} options={aliases.map(value => ({value,label:value === 'deepseek' ? 'DeepSeek' : '模拟模型'}))} /></div>
      <Button type="primary" loading={busy} disabled={!token || artifacts.length === 0 || artifacts.length > 10} onClick={() => void submit()}>创建检测任务</Button>
    </div>
    {artifacts.length > 10 && <Alert type="warning" title="每个任务最多 10 个快照，请移除多余输入。" />}
    {strategy === 'rules' ? <p>规则模式不会调用模型；未命中不代表安全。</p> : alias === 'fake' ? <Alert type="warning" title="模拟模型不执行真实分析，任务会明确标为部分完成。" /> : <p>DeepSeek 分析会发送脱敏内容，并计入服务器的调用预算。</p>}
    {!token && <p>{id ? '重新连接服务后可恢复此检测任务。' : '连接服务后可创建或查看任务。'}</p>}
    {error && <Alert type="error" title={error} role="alert" />}
    {scan && <article className="scan-detail" aria-label="任务详情">
      <h3><Tag color={scan.status === 'completed' ? 'success' : scan.status === 'failed' ? 'error' : 'processing'}>{STATUS[scan.status]}</Tag><code>{scan.id}</code></h3>
      <p>{scan.strategy} · {scan.model_alias} · 外部调用 {scan.call_count} 次 · 模型分块 {scan.result.completed_chunks ?? 0}/{scan.result.expected_chunks ?? 0}</p>
      {scan.budget && <p>调用预算：本任务 {scan.budget.scan_used}/{scan.budget.scan_limit} · 今日服务器 {scan.budget.daily_used}/{scan.budget.daily_limit}（次数，不是费用）</p>}
      {scan.result.coverage && scan.result.coverage.length > 0 && <CoverageLedger entries={scan.result.coverage} />}
      <AnalysisReceipt scan={scan} />
      {scan.attempts && scan.attempts.length > 0 && <details><summary>此前尝试（{scan.attempts.length}）</summary><ul>{scan.attempts.map(item => <li key={item.attempt}>第 {item.attempt + 1} 次：{STATUS[item.status as keyof typeof STATUS] ?? item.status}{item.error_code ? ` · ${item.error_code}` : ''} · 发现 {item.summary.finding_count ?? 0} 项</li>)}</ul></details>}
      {scan.error_code && <Alert type="warning" title={`任务错误：${scan.error_code}`} />}
      {scan.result.warnings?.map((warning, index) => <Alert key={index} type="warning" title={warning} />)}
      {['queued','running'].includes(scan.status) && <Button disabled={busy || scan.cancel_requested} onClick={() => void action('cancel')}>{scan.cancel_requested ? '正在取消' : '取消任务'}</Button>}
      {['partial','failed','cancelled'].includes(scan.status) && <Button disabled={busy || scan.retries >= 2} onClick={() => void action('retry')}>按当前配置重试</Button>}
      <p>发现 {findingTotal} 项；结果为静态风险判断，运行时效果尚未验证。</p>
      {findings.map(f => <div className="finding-card" key={f.id}>
        <h4><Tag>{f.cwe}</Tag><Tag>{f.severity}</Tag>{f.sources.join(' + ')} {f.severity_disagreement && <Tag color="warning">严重性判断有差异</Tag>}</h4>
        <p>{scan.artifacts.find(a => a.id === f.location.artifact_id)?.display_name ?? f.location.artifact_id} · {f.location.kind === 'source' ? `第 ${f.location.start_line}–${f.location.end_line} 行` : f.location.field} · {f.evidence_status}</p>
        <pre>{f.evidence}</pre><p>{f.explanation}</p><p>建议：{f.recommendation}</p>
        <details><summary>查看各来源判断</summary>{f.contributors.map((item,index) => <div key={index}><Tag>{item.sources.join(' + ')}</Tag><Tag>{item.severity}</Tag><p>{item.explanation}</p><p>{item.recommendation}</p></div>)}</details>
        <Button disabled={busy || f.location.kind !== 'source'} onClick={() => void repairFinding(f)}>生成{alias === 'fake' ? '模拟' : 'DeepSeek'}候选修复</Button>
      </div>)}
      {findingTotal > 100 && <div className="ingest-actions"><Button disabled={offset === 0} onClick={() => setOffset(Math.max(0,offset-100))}>上一页</Button><span>{offset+1}–{Math.min(offset+100,findingTotal)} / {findingTotal}</span><Button disabled={offset+100 >= findingTotal} onClick={() => setOffset(offset+100)}>下一页</Button></div>}
    </article>}
    <RepairPanel token={token} id={repairId} />
    <h3>最近任务</h3>
    {history.length === 0 ? <p>暂无任务记录。</p> : <ul className="scan-history">{history.map(item => <li key={item.id}><button onClick={() => selectScan(item.id)}>{STATUS[item.status]} · {item.artifacts.map(a=>a.display_name).join('、')} · {item.id.slice(0,8)}</button></li>)}</ul>}
  </section></ConfigProvider>;
}
