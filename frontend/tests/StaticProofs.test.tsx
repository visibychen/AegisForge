import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import StaticProofs from '../src/components/StaticProofs';
import type { ScanResult } from '../src/types/api';

it('supports historical results with no adjudication', () => {
  const { container } = render(<StaticProofs result={{} as ScanResult} />);
  expect(container).toBeEmptyDOMElement();
});

it('explains excluded clues without displaying untrusted criterion markup as HTML', () => {
  render(<StaticProofs result={{ adjudication: {
    version: 'adjudication-1.0', examined: 3, kept: 1, refuted: 2,
    by_criterion: {}, truncated: true,
    refuted_findings: [{ artifact_id: 'a', cwe: 'CWE-78', start_line: 2, end_line: 3,
      sources: ['llm'], criterion: '<img src=x onerror=alert(1)>' }],
  }} as ScanResult} />);
  expect(screen.getByText(/3 条线索中保留 1 条，排除 2 条/)).toBeInTheDocument();
  expect(screen.getByText(/不代表整个输入已验证安全/)).toBeInTheDocument();
  expect(screen.getByText(/该类型的静态判据未成立/)).toBeInTheDocument();
  expect(screen.getByText(/前 100 条/)).toBeInTheDocument();
  expect(document.querySelector('img')).toBeNull();
});
