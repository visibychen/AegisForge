import { useEffect, useMemo, useState } from 'react';
import { Alert } from 'antd';
import { getCompare, isAborted, isAuthFailure, isGone } from '../api/client';
import type { CompareView as Compare } from '../types/api';
import SourceLines from './SourceLines';
import type { Mark } from './SourceLines';

/** Original and candidate side by side (both redacted plain text) with where findings sit on each side. */
export default function CompareView({ token, repairId, onGone, onAuthLost }: {
  token: string; repairId: string; onGone?: () => void; onAuthLost?: () => void;
}) {
  const [data, setData] = useState<Compare | null>(null);
  const [revision, setRevision] = useState(0);
  const [hunk, setHunk] = useState(0);
  const [focusKey, setFocusKey] = useState(0);
  const [error, setError] = useState('');

  useEffect(() => {
    setData(null); setError('');
    if (!token || !repairId) return;
    const controller = new AbortController();
    getCompare(token, repairId, controller.signal)
      .then(result => { if (!controller.signal.aborted) setData(result.compare); })
      .catch(e => {
        if (isAborted(e) || controller.signal.aborted) return;
        if (isGone(e)) { onGone?.(); return; }
        if (isAuthFailure(e)) { setError('会话已失效，请重新连接服务后再查看对比。'); onAuthLost?.(); return; }
        setError(e instanceof Error ? e.message : '对比读取失败。');
      });
    return () => controller.abort();
  }, [token, repairId, revision]); // eslint-disable-line react-hooks/exhaustive-deps

  const original = useMemo<Mark[]>(() => data ? [
    ...data.hunks.filter(h => h.old_end >= h.old_start).map(h => ({ start: h.old_start, end: h.old_end, kind: 'changed' as const })),
    ...data.baseline.map(b => ({ start: b.start_line, end: b.end_line, kind: 'finding' as const, note: b.cwe })),
    { start: data.target.start_line, end: data.target.end_line, kind: 'target' as const, note: data.target.cwe },
  ] : [], [data]);
  const candidate = useMemo<Mark[]>(() => data ? [
    ...data.hunks.filter(h => h.new_end >= h.new_start).map(h => ({ start: h.new_start, end: h.new_end, kind: 'changed' as const })),
    ...(['persisting', 'preexisting', 'introduced'] as const).flatMap(kind =>
      data.after[kind].map(e => ({ start: e.start_line, end: e.end_line, kind, note: e.cwe + (e.by_source ? ` · ${Object.entries(e.by_source).map(([source, state]) => `${source}:${state}`).join(" / ")}` : "") }))),
  ] : [], [data]);

  if (error) return <><Alert type="error" title={error} role="alert" /><button onClick={() => setRevision(v => v + 1)}>重试读取对比</button></>;
  if (!data) return <p role="status">正在读取对比…</p>;
  return <section className="compare-view" aria-label="原文与候选对比">
    {data.archived && <Alert type="warning" title={`旧尝试候选：第 ${(data.finding_attempt ?? 0) + 1} 次检测，不代表当前第 ${(data.scan_attempt ?? 0) + 1} 次检测结果。`} />}
    {data.delta_status?.model !== 'done' && <p>模型复检未完成或未执行，未报告位置不能视为无风险。</p>}
    <div className="ingest-actions"><button disabled={!data.hunks.length} onClick={() => { setHunk(v => (v - 1 + data.hunks.length) % data.hunks.length); setFocusKey(v => v + 1); }}>上一处改动</button>
      <button disabled={!data.hunks.length} onClick={() => { setHunk(v => (v + 1) % data.hunks.length); setFocusKey(v => v + 1); }}>下一处改动</button></div>
    <p className="repair-impact">
      改动 {data.hunks.length} 处 · 仍存在 {data.after.persisting.length} · 原有未修复 {data.after.preexisting.length} · 新增风险 {data.after.introduced.length}
      （静态规则与模型复检所报告的位置，不是动态验证，也不证明没有其他风险）
    </p>
    {data.simulated && <Alert type="warning" title="模拟候选与原文相同，没有生成真实修复，因此没有可对比的改动。" />}
    <p className="repair-impact">原文摘要 {data.original.sha256.slice(0, 12)} · 候选摘要 {data.candidate.sha256.slice(0, 12)}（完整性记录，不是数字签名）</p>
    <div className="compare-grid">
      <div><h4>原文（脱敏）</h4><SourceLines label="原文源码" content={data.original.content} marks={original} focusLine={data.hunks[hunk]?.old_start ?? data.target.start_line} focusKey={focusKey} /></div>
      <div><h4>候选（脱敏）</h4><SourceLines label="候选源码" content={data.candidate.content} marks={candidate}
        focusLine={data.hunks[hunk]?.new_start} focusKey={focusKey} /></div>
    </div>
  </section>;
}
