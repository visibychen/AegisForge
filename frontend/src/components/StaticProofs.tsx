import type { ScanResult } from '../types/api';

const REASONS: Record<string, string> = {
  sql_text_has_no_untrusted_part: 'SQL 文本由受限的固定结构构成，数据通过参数传入',
  shell_command_has_no_untrusted_part: '命令文本是固定常量',
  argv_has_no_untrusted_part: '程序和参数均为固定常量',
  argv_data_operands: '受支持程序只将这些参数作为数据处理',
  markup_escapes_plain_values: 'HTML 文本上下文中的普通字符串会被转义',
  autoescaped_constant_template: '固定模板在所分析的 HTML 上下文中启用自动转义',
  json_encoded_in_script_data: '脚本数据采用 JSON 编码并转义了小于号',
  markup_of_constant_text: 'HTML 片段是固定常量',
  quoted_or_validated_shell_operands: '在所支持的 POSIX 命令形式中，参数已逐值引用或通过字符约束',
};

export default function StaticProofs({ result }: { result: ScanResult }) {
  const proof = result.adjudication;
  if (!proof) return null;
  return <details aria-label="静态复核记录"><summary>静态复核：{proof.examined} 条线索中保留 {proof.kept} 条，排除 {proof.refuted} 条</summary>
    <p>仅在满足明确的静态判据时排除线索；未知情况保留。排除某类线索不代表整个输入已验证安全，运行时效果仍需验证。</p>
    <ul>{proof.refuted_findings.map((item, index) => <li key={index}>{item.cwe} · 第 {item.start_line}–{item.end_line} 行 · {REASONS[item.criterion] ?? '该类型的静态判据未成立'}</li>)}</ul>
    {proof.truncated && <p>这里只展示前 100 条复核记录；总数以摘要为准。</p>}
  </details>;
}
