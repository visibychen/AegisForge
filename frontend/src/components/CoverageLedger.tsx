import { Tag } from 'antd';
import type { CoverageEntry } from '../types/api';

const MODEL: Record<CoverageEntry['model'], { text: string; color?: string }> = {
  succeeded: { text: '模型已分析', color: 'success' },
  failed: { text: '模型未完成', color: 'error' },
  simulated: { text: '模拟（未分析）', color: 'warning' },
  pending: { text: '待处理', color: 'processing' },
  not_requested: { text: '未请求模型' },
};
const RULES: Record<CoverageEntry['rules'], string> = {
  ran: '规则已运行', ast_unavailable: '规则未运行（语法不可解析）', not_requested: '未运行规则',
};

/** Per-chunk coverage ledger: shows exactly which regions were analysed by what. */
export default function CoverageLedger({ entries }: { entries: CoverageEntry[] }) {
  const gaps = entries.filter(entry => entry.model === 'failed' || entry.model === 'simulated' || entry.rules === 'ast_unavailable');
  return <section className="coverage-ledger" aria-label="分析覆盖台账">
    <h4>分析覆盖台账 <small>{entries.length} 个分块{gaps.length ? `，${gaps.length} 个存在缺口` : '，无缺口'}</small></h4>
    <p>未被模型成功分析的区域没有智能检测结论；“无发现”只对已覆盖区域有意义。</p>
    <ol>{entries.map(entry => <li key={`${entry.artifact_id}-${entry.chunk}`}>
      <span>{entry.display_name} · {entry.input_type === 'source' ? `第 ${entry.start_line}–${entry.end_line} 行` : `第 ${entry.chunk + 1} 段字段`}</span>
      <Tag>{RULES[entry.rules]}</Tag>
      <Tag color={MODEL[entry.model].color}>{MODEL[entry.model].text}</Tag>
      {entry.model === 'succeeded' && <span>模型发现 {entry.llm_findings} 项</span>}
      {entry.model_error && <code>{entry.model_error}{entry.failure_category ? ` / ${entry.failure_category}` : ''}</code>}
    </li>)}</ol>
  </section>;
}
