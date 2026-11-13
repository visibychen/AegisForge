import type { GateState, Repair } from '../types/api';

const STATE_TEXT: Record<GateState, string> = { passed: '通过', failed: '未通过', error: '工具异常', pending: '进行中', skipped: '未执行' };

/**
 * Plain-language explanation of what one candidate has and has not shown. It only summarises the
 * gate ledger and execution contract already on the repair; it never adds a verdict of its own.
 */
export default function RepairCard({ repair }: { repair: Repair }) {
  const gates = repair.gates ?? [];
  const passed = gates.filter(gate => gate.state === 'passed');
  const open = gates.filter(gate => gate.state !== 'passed');
  const impact = repair.impact;
  const contract = repair.checks.contract;
  return <section className="repair-card" aria-label="修复说明卡">
    <h4>修复说明卡</h4>
    <dl>
      <dt>候选来源</dt>
      <dd>{repair.simulated ? '模拟流程：候选与原文相同，没有真实修复' : `模型 ${repair.model_alias}${repair.model ? ` / ${repair.model}` : ''}，已生成候选补丁`}</dd>
      <dt>改动范围</dt>
      <dd>{impact ? `${impact.changed_lines}/${impact.total_lines} 行，${impact.hunks} 处，距目标 ${impact.distance} 行` : '没有改动统计'}</dd>
      <dt>已检查</dt>
      <dd>{passed.length > 0 ? `${passed.length} 项：${passed.map(gate => gate.label).join('、')}` : '尚无通过的检查'}</dd>
      <dt>仍未证明</dt>
      <dd>{open.length > 0 ? `${open.length} 项：${open.map(gate => `${gate.label}（${STATE_TEXT[gate.state]}）`).join('、')}` : '门禁账本中没有未完成项'}</dd>
      {contract && <>
        <dt>执行契约</dt>
        <dd>摘要 {contract.digest.slice(0, 12)} · 规则 {contract.versions.rules ?? '-'} · 提示词 {contract.versions.prompt ?? '-'}（完整性记录，不是数字签名）</dd>
      </>}
    </dl>
    <p className="repair-impact">静态复检与固定测试只说明检查过的部分，不证明候选没有其他漏洞或业务回归。</p>
  </section>;
}
