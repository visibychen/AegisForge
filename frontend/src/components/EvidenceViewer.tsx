import { useEffect, useMemo, useRef, useState } from 'react';
import { Alert, Button, Tag } from 'antd';
import { getInput, isAborted, isAuthFailure, isGone } from '../api/client';
import type { InputView, StoredFinding } from '../types/api';
import SourceLines from './SourceLines';
import type { Mark } from './SourceLines';

/**
 * Evidence navigator: shows the redacted input a finding points at, with every current finding of that
 * input located and the selected one emphasised. Source is plain text with line numbers; HTTP is a field list.
 */
export default function EvidenceViewer({ token, scanId, findings, selectedId, onSelect, onGone, onAuthLost }: {
  token: string; scanId: string; findings: StoredFinding[]; selectedId: string;
  onSelect: (id: string) => void; onGone?: () => void; onAuthLost?: () => void;
}) {
  const selected = findings.find(f => f.id === selectedId);
  const artifactId = selected?.location.artifact_id ?? '';
  const [input, setInput] = useState<InputView | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const cache = useRef(new Map<string, InputView>());

  useEffect(() => {
    if (!token || !artifactId) { setInput(null); setLoading(false); return; }
    const key = `${scanId}:${artifactId}`;
    const cached = cache.current.get(key);
    setError('');
    if (cached) { setInput(cached); setLoading(false); return; }
    setInput(null); setLoading(true);
    const controller = new AbortController();
    getInput(token, scanId, artifactId, controller.signal)
      .then(data => {
        if (controller.signal.aborted) return; // another finding was selected meanwhile
        cache.current.set(key, data.input); setInput(data.input);
      })
      .catch(e => {
        if (isAborted(e) || controller.signal.aborted) return; // superseded by a newer selection
        if (isGone(e)) { onGone?.(); return; }
        if (isAuthFailure(e)) { setError('会话已失效，请重新连接服务后再查看证据。'); onAuthLost?.(); return; }
        setError(e instanceof Error ? e.message : '证据读取失败。');
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [token, scanId, artifactId]); // eslint-disable-line react-hooks/exhaustive-deps

  const here = useMemo(() => findings.filter(f => f.location.artifact_id === artifactId), [findings, artifactId]);
  const marks = useMemo<Mark[]>(() => here.flatMap(f => f.location.kind === 'source'
    ? [{ start: f.location.start_line, end: f.location.end_line, kind: f.id === selectedId ? 'selected' as const : 'finding' as const, note: f.cwe, id: f.id }]
    : []), [here, selectedId]);

  if (!selected) return null;
  const index = findings.findIndex(f => f.id === selectedId);
  const step = (delta: number) => onSelect(findings[(index + delta + findings.length) % findings.length].id);
  return <section className="evidence-viewer" aria-label="证据导航">
    <h4>证据导航 <Tag>{selected.cwe}</Tag><Tag>{selected.severity}</Tag>
      {input && <small>{input.display_name} · {input.input_type === 'source' ? '源码' : 'HTTP 请求'}</small>}</h4>
    <p className="repair-impact">以下为服务端脱敏后的纯文本，仅作定位参考；静态命中不等于已确认漏洞。</p>
    <div className="ingest-actions">
      <Button size="small" disabled={findings.length < 2} onClick={() => step(-1)}>上一条发现</Button>
      <span>{index + 1} / {findings.length}</span>
      <Button size="small" disabled={findings.length < 2} onClick={() => step(1)}>下一条发现</Button>
    </div>
    {error && <Alert type="error" title={error} role="alert" />}
    {loading && <p role="status">正在读取输入快照…</p>}
    {input && selected.location.kind === 'source' && <SourceLines label={`源码与发现位置：${input.display_name}`} content={input.content}
      marks={marks} focusLine={selected.location.start_line} onActivate={mark => mark.id && onSelect(mark.id)} />}
    {input && selected.location.kind === 'http' && <HttpFields input={input} here={here} selectedId={selectedId} onSelect={onSelect} />}
  </section>;
}

function HttpFields({ input, here, selectedId, onSelect }: {
  input: InputView; here: StoredFinding[]; selectedId: string; onSelect: (id: string) => void;
}) {
  const byField = new Map<string, StoredFinding[]>();
  for (const f of here) if (f.location.kind === 'http') byField.set(f.location.field, [...(byField.get(f.location.field) ?? []), f]);
  return <div className="http-fields" role="group" aria-label={`HTTP 字段与发现位置：${input.display_name}`}>
    {Object.entries(input.fields).map(([field, value]) => {
      const meta = input.field_meta[field];
      const owners = byField.get(field) ?? [];
      const chosen = owners.some(f => f.id === selectedId);
      return <div key={field} className={`http-field${chosen ? ' mark-selected' : owners.length ? ' mark-finding' : ''}`} aria-current={chosen ? 'true' : undefined}>
        <span className="http-field-name">{meta ? `${meta.part} · ${meta.name}` : field}{meta?.masked ? '（已脱敏）' : ''}</span>
        <code>{value}</code>
        {owners.length > 0 && <span className="line-tags">
          <span className="mark-tag">{chosen ? '当前所选发现' : '检测发现'} · {owners[0].cwe}</span>
          {!chosen && <Button size="small" onClick={() => onSelect(owners[0].id)}>选择此字段的发现</Button>}
        </span>}
      </div>;
    })}
  </div>;
}
