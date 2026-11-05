import { useState } from 'react';
import { Alert, Button, Input, Select, Tag } from 'antd';
import { uploadArtifact } from '../api/client';
import type { ArtifactPreview } from '../types/api';

export default function IngestPanel({ token, onArtifact }: { token: string; onArtifact?: (a: ArtifactPreview) => void }) {
  const [kind, setKind] = useState<'source' | 'http'>('source');
  const [content, setContent] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [artifact, setArtifact] = useState<ArtifactPreview | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit() {
    setBusy(true); setError(''); setArtifact(null);
    try {
      const result = await uploadArtifact(token, kind, file?.name ?? (kind === 'source' ? 'pasted.py' : 'pasted.http'), file ?? new Blob([content]));
      setArtifact(result.artifact); onArtifact?.(result.artifact);
    } catch (e) { setError(e instanceof Error ? e.message : '输入提交失败。'); }
    finally { setBusy(false); }
  }
  return <section className="surface ingest-panel" aria-labelledby="ingest-title" id="new-scan">
    <div className="section-heading"><h2 id="ingest-title">新建检测 · 输入预览</h2><Tag>静态特征</Tag></div>
    <p>提交 Python 文件或离线 HTTP 请求。单文件上限 2 MiB，规范化内容上限 80,000 字符；原始快照仅保存在本地私有目录。</p>
    <label htmlFor="input-kind">输入类型</label>
    <Select id="input-kind" aria-label="输入类型" value={kind} onChange={value => { setKind(value); setFile(null); setArtifact(null); }} options={[{ value: 'source', label: 'Python 源码' }, { value: 'http', label: 'HTTP 请求文本' }]} />
    <label htmlFor="input-file">选择文件（优先于粘贴内容）</label>
    <input id="input-file" type="file" accept={kind === 'source' ? '.py' : '.http,.req,.txt'} onChange={event => { setFile(event.target.files?.[0] ?? null); setArtifact(null); }} />
    <label htmlFor="input-content">或粘贴内容</label>
    <Input.TextArea id="input-content" value={content} onChange={event => { setContent(event.target.value); setArtifact(null); }} rows={8} placeholder={kind === 'source' ? '粘贴 Python 源码' : 'GET / HTTP/1.1\nHost: example.invalid\n\n'} />
    <div className="ingest-actions"><Button onClick={() => { setFile(null); setContent(kind === 'source' ? "from flask import request\nimport os\n\ndef index():\n    os.system(request.args['cmd'])\n" : 'GET /?q=%3Cscript%3E HTTP/1.1\nHost: example.invalid\n\n'); setArtifact(null); }}>载入开发示例</Button><Button type="primary" loading={busy} disabled={!token || (!file && !content.trim())} onClick={() => void submit()}>保存并预览特征</Button></div>
    {!token && <p>连接服务后即可提交输入。</p>}
    {error && <Alert type="error" title={error} role="alert" />}
    {artifact && <div className="artifact-preview">
      <h3>脱敏预览 · {artifact.display_name}</h3>
      <p>{artifact.size_bytes} 字节 · {artifact.chunk_count} 个分析分块 · {artifact.parser_version}</p>
      {artifact.warnings.map((w, i) => <Alert key={i} type="warning" title={w} />)}
      <pre>{artifact.content}</pre>
      <p>规则线索 {artifact.rule_findings.length} 项；规则无命中不代表安全。</p>
      {artifact.rule_findings.map((f, i) => <div key={i}><Tag>{f.cwe}</Tag>{f.explanation}<pre>{f.evidence}</pre></div>)}
    </div>}
  </section>;
}
