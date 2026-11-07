import { Button } from 'antd';
import type { Scan } from '../types/api';

export default function AnalysisReceipt({ scan }: { scan: Scan }) {
  const receipt = scan.receipt;
  if (!receipt?.plan_digest) return null;
  function download() {
    // Receipt is a server whitelist. Do not export the full scan, warnings, names or evidence.
    const payload = { receipt, status: scan.status, attempt: scan.attempt ?? 0,
      analysis_complete: scan.result.analysis_complete ?? false,
      coverage: scan.result.coverage?.map(({ artifact_id, chunk, start_line, end_line, rules, model, model_error, failure_category, llm_findings }) =>
        ({ artifact_id, chunk, start_line, end_line, rules, model, model_error, failure_category, llm_findings })) ?? [] };
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url; link.download = `aegisforge-${scan.id}-receipt.json`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return <details className="analysis-receipt"><summary>检测凭证 · 输入与分析方案</summary>
    <p>用于核对输入、配置与覆盖范围。凭证没有数字签名，也不保证模型判断正确或输出可确定性复现。</p>
    <p>输入摘要 <code>{receipt.input_digest}</code></p>
    <p>方案摘要 <code>{receipt.plan_digest}</code></p>
    <p>模型 {receipt.configuration.model ?? receipt.configuration.model_alias} · 提示词 {receipt.configuration.versions.prompt}</p>
    <Button onClick={download}>下载检测凭证</Button>
  </details>;
}
