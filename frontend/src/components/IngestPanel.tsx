import { useEffect, useRef, useState } from 'react';
import { Alert, Button, ConfigProvider, Input, Select, Tag } from 'antd';
import { ApiError, uploadArtifact } from '../api/client';
import type { ArtifactPreview, Finding } from '../types/api';

const SAMPLES = {
  source: "from flask import request\nimport os\n\ndef index():\n    os.system(request.args['cmd'])\n",
  http: 'GET /?q=%3Cscript%3E HTTP/1.1\nHost: example.invalid\n\n',
};

const FEATURE_LABELS = { call: '函数调用', string_expression: '字符串表达式', input_source: '输入来源', text_call_hint: '文本调用线索' };

function locate(finding: Finding, preview: ArtifactPreview): string {
  if (finding.location.kind === 'source') {
    const { start_line: start, end_line: end } = finding.location;
    return start === end ? `第 ${start} 行` : `第 ${start}–${end} 行`;
  }
  const meta = preview.field_meta[finding.location.field];
  return meta ? `${finding.location.field} · ${meta.name}` : finding.location.field;
}

export default function IngestPanel({ token }: { token: string }) {
  const [kind, setKind] = useState<'source' | 'http'>('source');
  const [content, setContent] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [fileInputKey, setFileInputKey] = useState(0);
  const [artifact, setArtifact] = useState<ArtifactPreview | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  // Every input change bumps the generation, so a late response can never show a stale preview.
  const request = useRef<{ generation: number; controller: AbortController | null }>({ generation: 0, controller: null });

  function invalidate() {
    request.current.generation += 1;
    request.current.controller?.abort();
    request.current.controller = null;
    setBusy(false);
    setArtifact(null);
    setError('');
  }

  function clearFile() {
    setFile(null);
    setFileInputKey(key => key + 1); // Remount the native input so it no longer shows a stale name.
  }

  useEffect(() => () => request.current.controller?.abort(), []);
  useEffect(() => { invalidate(); }, [token]); // A new session token invalidates earlier previews.

  async function submit() {
    invalidate();
    const generation = request.current.generation;
    const controller = new AbortController();
    request.current.controller = controller;
    setBusy(true);
    try {
      const name = file?.name ?? (kind === 'source' ? 'pasted.py' : 'pasted.http');
      const result = await uploadArtifact(token, kind, name, file ?? new Blob([content]), controller.signal);
      if (request.current.generation === generation) setArtifact(result.artifact);
    } catch (exception) {
      if (request.current.generation === generation) {
        setError(exception instanceof ApiError ? exception.message : '输入提交失败，请稍后重试。');
      }
    } finally {
      if (request.current.generation === generation) {
        setBusy(false);
        request.current.controller = null;
      }
    }
  }

  // The portaled wave can retain desktop coordinates for a frame after resizing.
  // Input controls stay static; decorative workspace motion has its own user control.
  return <ConfigProvider wave={{ disabled: true }}><section className="surface ingest-panel" aria-labelledby="ingest-title" id="new-scan">
    <div className="section-heading"><h2 id="ingest-title">新建检测 · 输入预览</h2><Tag>静态特征</Tag></div>
    <p>提交 Python 文件或离线 HTTP 请求。单文件上限 2 MiB，内容上限 80,000 字符；原始快照仅保存在本地私有目录，预览与规则证据均已脱敏（尽力而为，并非绝对）。</p>
    <label htmlFor="input-kind">输入类型</label>
    <Select id="input-kind" aria-label="输入类型" value={kind}
      onChange={value => { invalidate(); clearFile(); setKind(value); }}
      options={[{ value: 'source', label: 'Python 源码' }, { value: 'http', label: 'HTTP 请求文本' }]} />
    <label htmlFor="input-file">选择文件（优先于粘贴内容）</label>
    <input key={fileInputKey} id="input-file" type="file" accept={kind === 'source' ? '.py' : '.http,.req,.txt'}
      onChange={event => { invalidate(); setFile(event.target.files?.[0] ?? null); }} />
    <label htmlFor="input-content">或粘贴内容</label>
    <Input.TextArea id="input-content" value={content} rows={8}
      onChange={event => { invalidate(); setContent(event.target.value); }}
      placeholder={kind === 'source' ? '粘贴 Python 源码' : 'GET / HTTP/1.1\nHost: example.invalid\n\n'} />
    <div className="ingest-actions">
      <Button onClick={() => { invalidate(); clearFile(); setContent(SAMPLES[kind]); }}>载入开发示例</Button>
      <Button type="primary" loading={busy} disabled={!token || (!file && !content.trim())} onClick={() => void submit()}>保存并预览特征</Button>
    </div>
    {!token && <p>连接服务后即可提交输入。</p>}
    {error && <Alert type="error" title={error} role="alert" />}
    {artifact && <div className="artifact-preview">
      <h3>脱敏预览 · {artifact.display_name}</h3>
      <p>{artifact.size_bytes} 字节 · {artifact.chunk_count} 个分析分块 · {artifact.parser_version} · {artifact.rule_version}</p>
      {artifact.warnings.map((warning, index) => <Alert key={index} type="warning" title={warning} />)}
      <pre>{artifact.content}</pre>
      {artifact.features.length > 0 && <details className="input-features">
        <summary>查看输入特征（{artifact.features.length} 项）</summary>
        <ul>{artifact.features.slice(0, 30).map((feature, index) => <li key={index}>
          <Tag>{FEATURE_LABELS[feature.kind]}</Tag>第 {feature.line} 行 {feature.name ?? ''}
          {feature.sink_candidate && <Tag>关注调用 · {feature.sink_candidate.toUpperCase()}</Tag>}
        </li>)}</ul>
        {artifact.features.length > 30 && <p>当前展示前 30 项。</p>}
        <p>输入特征是分析线索，不是漏洞结论。</p>
      </details>}
      <p>规则线索 {artifact.rule_findings.length} 项{artifact.rule_findings_truncated ? '（已达上限，未全部展示）' : ''}；规则无命中不代表安全。</p>
      {artifact.rule_findings.map((finding, index) => <div key={index}>
        <Tag>{finding.cwe}</Tag>{finding.evidence_truncated && <Tag color="warning">证据已截断</Tag>}
        <span>{locate(finding, artifact)}</span> {finding.explanation}<pre>{finding.evidence}</pre>
      </div>)}
    </div>}
  </section></ConfigProvider>;
}
