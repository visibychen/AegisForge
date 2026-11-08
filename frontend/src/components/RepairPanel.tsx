import { useEffect, useState } from 'react';
import { Alert, Button, Tag } from 'antd';
import { getRepair, cancelRepair, requestValidation, downloadRepair } from '../api/client';
import type { Repair } from '../types/api';

export default function RepairPanel({ token, id }: { token: string; id: string }) {
  const [repair, setRepair] = useState<Repair | null>(null);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let live = true;
    setRepair(null); setError('');
    if (!token || !id) return;
    const timer = setInterval(() => void poll(), 1500);
    let running = false;
    async function poll() {
      if (running) return;
      running = true;
      try {
        const data = await getRepair(token, id);
        if (live) setRepair(data.repair);
        if (['failed','cancelled'].includes(data.repair.status) || data.repair.status === 'candidate' && !['pending','running'].includes(data.repair.dynamic.status ?? '')) clearInterval(timer);
      } catch (e) { if (live) setError(e instanceof Error ? e.message : '修复读取失败。'); clearInterval(timer); }
      finally { running = false; }
    }
    void poll();
    return () => { live = false; clearInterval(timer); };
  }, [token, id, revision]);
  async function action(kind: 'cancel' | 'validate') {
    try { await (kind === 'cancel' ? cancelRepair(token, id) : requestValidation(token, id)); setRevision(v => v + 1); }
    catch (e) { setError(e instanceof Error ? e.message : '操作失败。'); }
  }
  if (!id) return null;
  return <section className="repair-panel" aria-label="候选修复详情">
    <h3>候选修复 <Tag>{repair?.status ?? '加载中'}</Tag></h3>
    {error && <Alert type="error" title={error} />}
    {repair && <>
      <p><Tag>{repair.validation_status}</Tag>{repair.model_alias} · 外部调用 {repair.call_count} 次</p>
      <p>静态检查与模型复检不能代替动态安全及业务验证。普通上传没有受控动态证据。</p>
      {repair.error_code && <Alert type="warning" title={repair.error_code} />}
      {['queued','running'].includes(repair.status) && <Button onClick={() => void action('cancel')}>取消修复</Button>}
      {repair.status === 'candidate' && <>
        <p>{repair.checks.mode === 'fake' ? '模拟流程，没有生成真实修复。' : repair.checks.explanation}</p>
        <p>语法：{repair.checks.syntax} · 规则/模型静态复检：{repair.checks.static_passed ? '通过' : '未通过或未完成'}</p>
        <pre>{repair.diff || '候选没有产生文本差异。'}</pre>
        <div className="ingest-actions"><Button onClick={() => void downloadRepair(token, id, 'diff').catch(e => setError(e.message))}>下载补丁</Button><Button onClick={() => void downloadRepair(token, id, 'source').catch(e => setError(e.message))}>下载候选源码</Button><Button disabled={['pending','running'].includes(repair.dynamic.status ?? '')} onClick={() => void action('validate')}>申请受控动态验证</Button></div>
        <p>动态验证：{repair.dynamic.status ?? 'unverified'}；申请后需独立验证 runner 处理，缺环境会明确报错。</p>
        {repair.dynamic.tests?.map(test => <p key={test.name}>{test.name}：{test.passed ? '通过' : '失败'}</p>)}
      </>}
    </>}
  </section>;
}
