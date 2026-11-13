import { Tag } from 'antd';
import type { Gate, GateState, PatchImpact } from '../types/api';

const STATE: Record<GateState, { text: string; color?: string }> = {
  passed: { text: '通过', color: 'success' },
  failed: { text: '未通过', color: 'error' },
  error: { text: '工具异常', color: 'error' },
  pending: { text: '进行中', color: 'processing' },
  skipped: { text: '未执行' },
};
const NOTES: Record<string, string> = {
  removed_definition: '删除或改名了原有的函数/类',
  signature_changed: '改变了函数参数',
  decorator_changed: '改变了装饰器（如路由）',
  forbidden_call_added: '新增了 eval/exec/pickle 等禁止调用',
  wide_rewrite: '改动范围过大（接近整体重写）',
  wide_change: '改动范围较大',
  far_edit: '包含远离漏洞位置的代码改动',
  risky_call_added: '新增了 os.system 等高风险调用',
  shell_true_added: '新增了 shell=True',
  function_gutted: '目标函数语句数明显减少',
  return_removed: '目标函数不再有返回值',
};

/** One row per verification gate: the reason a verdict is not "passed" is always visible. */
export default function RepairGates({ gates, impact }: { gates: Gate[]; impact?: PatchImpact | null }) {
  const notes = impact ? [...impact.violations.map(code => ({ code, hard: true })), ...impact.warnings.map(code => ({ code, hard: false }))] : [];
  return <section className="repair-gates" aria-label="修复门禁账本">
    <h4>修复门禁账本 <small>{gates.filter(g => g.state === 'passed').length}/{gates.length} 通过</small></h4>
    <ol>{gates.map(gate => <li key={gate.id}>
      <Tag color={STATE[gate.state].color}>{STATE[gate.state].text}</Tag>
      <span>{gate.label}</span>
      {gate.detail && <small>{gate.detail}</small>}
    </li>)}</ol>
    {impact && <p className="repair-impact">变更影响：改动 {impact.changed_lines}/{impact.total_lines} 行（{Math.round(impact.change_ratio * 100)}%），{impact.hunks} 处，距目标 {impact.distance} 行{impact.imports_added.length > 0 && `；新增导入 ${impact.imports_added.join('、')}`}</p>}
    {notes.length > 0 && <ul className="repair-notes">{notes.map(note => <li key={note.code}>
      <Tag color={note.hard ? 'error' : 'warning'}>{note.hard ? '拒绝原因' : '提示'}</Tag>{NOTES[note.code] ?? note.code}
    </li>)}</ul>}
  </section>;
}
