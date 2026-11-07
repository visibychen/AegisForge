import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import CoverageLedger from '../src/components/CoverageLedger';
import type { CoverageEntry } from '../src/types/api';

const entry: CoverageEntry = { artifact_id: 'a', display_name: 'sample.py', input_type: 'source', chunk: 0,
  start_line: 1, end_line: 10, rules: 'pending', model: 'pending', model_error: null, failure_category: null, llm_findings: 0 };

it('counts unprocessed regions as gaps instead of completed analysis', () => {
  render(<CoverageLedger entries={[entry]} />);
  expect(screen.getByText(/1 个存在缺口/)).toBeInTheDocument();
  expect(screen.getByText('规则待处理')).toBeInTheDocument();
  expect(screen.queryByText(/无缺口/)).not.toBeInTheDocument();
});

it('explicitly distinguishes rules-only coverage from model analysis', () => {
  render(<CoverageLedger entries={[{ ...entry, rules: 'ran', model: 'not_requested' }]} />);
  expect(screen.getByText('仅规则模式，未做模型分析。')).toBeInTheDocument();
  expect(screen.getByText('未请求模型')).toBeInTheDocument();
});
