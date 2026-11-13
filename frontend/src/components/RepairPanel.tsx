import { useEffect, useState } from 'react';
import { Alert, Button, Tag } from 'antd';
import { cancelRepair, downloadRepair, getRepair, isAborted, isAuthFailure, isGone, requestValidation } from '../api/client';
import type { Repair } from '../types/api';
import CompareView from './CompareView';
import RepairCard from './RepairCard';
import RepairGates from './RepairGates';

const RECONNECT = '会话已失效，请重新连接服务后再查看候选修复。';
const GONE = '该候选修复已不存在（所属检测任务可能已移出历史）。';
const VERDICT: Record<Repair['validation_status'], { text: string; color?: string }> = {
  passed: { text: '受控验证全部通过', color: 'success' },
  failed: { text: '未通过', color: 'error' },
  error: { text: '验证异常', color: 'error' },
  unverified: { text: '未验证' },
};
const STATUS: Record<string, string> = {
  queued: '排队中', running: '生成中', candidate: '候选已生成', failed: '失败', cancelled: '已取消',
};
const DYNAMIC: Record<string, string> = {
  pending: '等待独立验证 runner', running: '容器中验证运行中', passed: '全部固定测试通过',
  failed: '存在失败的固定测试', error: '验证环境异常', cancelled: '已取消',
};
const ERRORS: Record<string, string> = {
  REPAIR_ARCHIVED: '旧尝试候选不能重新验证',
  PATCH_SCOPE: '候选改动超出允许范围', PATCH_SYNTAX: '候选未通过语法校验', PATCH_CONFLICT: '编辑原文与快照不一致',
  PATCH_RANGE: '编辑范围越界或重叠', PATCH_SENSITIVE: '候选含需要脱敏的内容', PATCH_NEWLINE: '替换文本缺少行结束',
  PATCH_ENCODING: '候选含不被接受的字符', PATCH_SIZE: '候选为空或过大', PATCH_DIFF_MISMATCH: '补丁无法还原候选',
  REPAIR_STALE: '检测结果已变化，请重新检测后再修复', TASK_TIMEOUT: '达到总时限', LEASE_EXHAUSTED: '多次恢复仍未完成',
  MODEL_RATE_LIMIT: '模型限流', MODEL_AUTH_FAILED: '模型鉴权失败', MODEL_INVALID_OUTPUT: '模型输出未通过校验',
  MODEL_CALL_BUDGET: '调用预算已用尽', MODEL_DAILY_BUDGET: '今日调用上限', REPAIR_INTERNAL: '内部错误',
  VALIDATION_TIMEOUT: '容器验证超时', VALIDATION_PROTOCOL: '验证结果格式不可信', VALIDATION_NO_RESULT: '验证器没有返回结果',
  VALIDATION_ENVIRONMENT: 'Docker 或验证镜像不可用', VALIDATION_INTERRUPTED: '验证器中途中断', VALIDATOR_IMAGE_STALE: '验证镜像需要重新构建',
  CONTROLLED_SAMPLE_REQUIRED: '不是登记的受控样例',
};
const explain = (code?: string | null) => (code ? `${ERRORS[code] ?? '未归类错误'}（${code}）` : '');
const LIVE = new Set(['pending', 'running']);

export default function RepairPanel({ token, id, scanId, scanAttempt, onGone, onAuthLost, onChanged }: {
  token: string; id: string; scanId?: string; scanAttempt?: number;
  /** The repair (or its scan) no longer exists: the owner clears the selection and the URL. */
  onGone?: () => void;
  /** The session is unusable: the owner decides how to ask for a reconnect. */
  onAuthLost?: () => void;
  /** The repair reached a state worth refreshing lists for (candidate ready, failed, ...). */
  onChanged?: () => void;
}) {
  const [repair, setRepair] = useState<Repair | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const [comparing, setComparing] = useState(false);

  useEffect(() => {
    let live = true;
    let failures = 0;
    let stopped = false;
    const controller = new AbortController();
    setRepair(null); setError(''); setComparing(false);
    if (!token || !id) return;
    const timer = setInterval(() => void poll(), 1500);
    let running = false;
    async function poll() {
      if (running || stopped) return;
      running = true;
      try {
        const data = await getRepair(token, id, controller.signal);
        if (!live) return;
        failures = 0;
        if (scanId && data.repair.scan_id !== scanId) {
          stopped = true; clearInterval(timer);
          if (live) { setRepair(null); setError('该候选修复不属于当前检测任务。'); }
          return;
        }
        setRepair(data.repair); setError('');
        const { status, dynamic } = data.repair;
        if (['failed', 'cancelled'].includes(status) || (status === 'candidate' && !LIVE.has(dynamic.status ?? ''))) {
          stopped = true; clearInterval(timer);
          onChanged?.();
        }
      } catch (e) {
        if (!live || isAborted(e)) return;
        failures += 1;
        // Authorization problems never heal by retrying, and a missing repair never comes back;
        // transient network errors get a few tries.
        if (isGone(e)) {
          stopped = true; clearInterval(timer); setRepair(null); setError(GONE); onGone?.();
          return;
        }
        if (isAuthFailure(e) || failures >= 5) { stopped = true; clearInterval(timer); }
        setError(isAuthFailure(e) ? RECONNECT : e instanceof Error ? e.message : '修复读取失败。');
        if (isAuthFailure(e)) onAuthLost?.();
      } finally { running = false; }
    }
    void poll();
    return () => { live = false; controller.abort(); clearInterval(timer); };
  }, [token, id, scanId, scanAttempt, revision]); // eslint-disable-line react-hooks/exhaustive-deps

  async function act(task: () => Promise<unknown>) {
    setBusy(true); setError('');
    try { await task(); setRevision(v => v + 1); }
    catch (e) {
      if (isGone(e)) { setError(GONE); onGone?.(); }
      else {
        setError(isAuthFailure(e) ? RECONNECT : e instanceof Error ? e.message : '操作失败。');
        if (isAuthFailure(e)) onAuthLost?.();
      }
    }
    finally { setBusy(false); }
  }
  if (!id) return null;
  const verdict = repair ? VERDICT[repair.validation_status] : null;
  const dynamicLive = LIVE.has(repair?.dynamic.status ?? '');
  return <section className="repair-panel" aria-label="候选修复详情">
    <h3>候选修复 <Tag>{repair ? STATUS[repair.status] ?? repair.status : '加载中'}</Tag></h3>
    {error && <Alert type="error" title={error} role="alert" />}
    {repair && <>
      <p>{verdict && <Tag color={verdict.color}>{verdict.text}</Tag>}{repair.simulated ? '模拟模型' : repair.model_alias} · 外部调用 {repair.call_count} 次</p>
      {repair.archived && <Alert type="warning" title="旧尝试候选：仅作历史记录，不代表当前检测结果，不能重新申请动态验证。" />}
      {repair.simulated && <Alert type="warning" title="模拟流程只演示处理链路：候选与原文相同，没有生成真实修复，也不会显示为已验证。" />}
      <p>静态复检与模型复检不能代替动态安全及业务验证；通过只表示本次固定测试集通过，不等于没有其他漏洞。</p>
      {repair.error_code && <Alert type="warning" title={explain(repair.error_code)} />}
      {repair.checks.review?.status === 'failed' && <Alert type="warning" title={`模型复检未完成：${explain(repair.checks.review.error)}。候选已保留，当前为“未验证”。`} />}
      {['queued', 'running'].includes(repair.status) && <Button disabled={busy} onClick={() => void act(() => cancelRepair(token, id))}>取消修复</Button>}
      {repair.checks.contract && <details><summary>修复执行契约</summary>
        <p>记录本次实际模型、规则与提示词版本及快照摘要；摘要用于完整性核对。</p>
        <pre>{JSON.stringify(repair.checks.contract, null, 2)}</pre>
      </details>}
      {repair.gates && repair.gates.length > 0 && <RepairGates gates={repair.gates} impact={repair.impact} />}
      {repair.status === 'candidate' && <RepairCard repair={repair} />}
      {repair.status === 'candidate' && <>
        <p>{repair.simulated ? '' : repair.checks.explanation}</p>
        <pre>{repair.diff || '候选没有产生文本差异。'}</pre>
        <div className="ingest-actions">
          <Button aria-expanded={comparing} onClick={() => setComparing(v => !v)}>{comparing ? '收起对比' : '对比原文与候选'}</Button>
          <Button onClick={() => void downloadRepair(token, id, 'diff').catch(e => setError(e.message))}>下载补丁</Button>
          <Button onClick={() => void downloadRepair(token, id, 'source').catch(e => setError(e.message))}>下载候选源码</Button>
          <Button disabled={busy || dynamicLive || repair.archived} onClick={() => void act(() => requestValidation(token, id))}>申请受控动态验证</Button>
          {dynamicLive && <Button disabled={busy} onClick={() => void act(() => cancelRepair(token, id))}>取消动态验证</Button>}
        </div>
        {comparing && <CompareView token={token} repairId={id} onGone={() => { setError(GONE); onGone?.(); }} onAuthLost={onAuthLost} />}
        <p>动态验证：{repair.dynamic.status ? DYNAMIC[repair.dynamic.status] ?? repair.dynamic.status : '未请求'}
          {repair.dynamic.error_code ? `；${explain(repair.dynamic.error_code)}` : ''}
          {repair.dynamic.status === 'pending' ? '；需要另行启动独立验证 runner。' : ''}</p>
        {repair.dynamic.tests?.map(test => <p key={test.name}>{test.name}：{test.passed ? '通过' : '失败'}</p>)}
        {repair.dynamic.digest && <p className="repair-impact">验证记录摘要 {repair.dynamic.digest.slice(0, 12)} · 候选 {repair.dynamic.candidate_sha256?.slice(0, 12)}（完整性记录，不是数字签名）</p>}
      </>}
    </>}
  </section>;
}
