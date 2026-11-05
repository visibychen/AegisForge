import { act, fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import IngestPanel from '../src/components/IngestPanel';
import { uploadArtifact } from '../src/api/client';
import type { ArtifactPreview } from '../src/types/api';

vi.mock('../src/api/client', async importOriginal => {
  const original = await importOriginal<typeof import('../src/api/client')>();
  return { ...original, uploadArtifact: vi.fn() };
});

const preview: ArtifactPreview = {
  id: 'a', input_type: 'source', display_name: 'pasted.py', sha256: '0'.repeat(64), size_bytes: 8,
  parser_version: 'inputs-1.1', rule_version: 'rules-1.1', content: 'print(1)', fields: {}, field_meta: {},
  features: [], warnings: [], chunk_count: 1, rule_findings: [], rule_findings_truncated: false,
};

describe('ingest panel', () => {
  it('discards a late response once the input has changed', async () => {
    let resolve!: (value: { artifact: ArtifactPreview }) => void;
    vi.mocked(uploadArtifact).mockImplementationOnce(() => new Promise(done => { resolve = done; }));
    render(<IngestPanel token="session" />);
    const editor = screen.getByLabelText('或粘贴内容');
    fireEvent.change(editor, { target: { value: 'print(1)' } });
    fireEvent.click(screen.getByRole('button', { name: /保存并预览特征/ }));
    fireEvent.change(editor, { target: { value: 'print(2)' } });
    await act(async () => resolve({ artifact: preview }));
    expect(screen.queryByText(/脱敏预览/)).not.toBeInTheDocument();
  });

  it('shows the preview when the input is unchanged', async () => {
    vi.mocked(uploadArtifact).mockResolvedValueOnce({ artifact: preview });
    render(<IngestPanel token="session" />);
    fireEvent.change(screen.getByLabelText('或粘贴内容'), { target: { value: 'print(1)' } });
    fireEvent.click(screen.getByRole('button', { name: /保存并预览特征/ }));
    expect(await screen.findByText(/脱敏预览/)).toBeInTheDocument();
  });

  it('labels truncated evidence without altering the excerpt', async () => {
    const finding = {
      category: 'cmdi' as const, cwe: 'CWE-78', severity: 'high', evidence: 'os.system(x', evidence_truncated: true,
      explanation: 'e', recommendation: 'r', sources: ['rule'], evidence_status: 'potential',
      location: { kind: 'source' as const, artifact_id: 'a', start_line: 2, end_line: 9 },
    };
    vi.mocked(uploadArtifact).mockResolvedValueOnce({ artifact: { ...preview, rule_findings: [finding] } });
    render(<IngestPanel token="session" />);
    fireEvent.change(screen.getByLabelText('或粘贴内容'), { target: { value: 'print(1)' } });
    fireEvent.click(screen.getByRole('button', { name: /保存并预览特征/ }));
    expect(await screen.findByText('证据已截断')).toBeInTheDocument();
    expect(screen.getByText('os.system(x')).toBeInTheDocument();
  });

  it('clears the native file input when switching to the sample', () => {
    render(<IngestPanel token="session" />);
    const input = screen.getByLabelText('选择文件（优先于粘贴内容）') as HTMLInputElement;
    fireEvent.change(input, { target: { files: [new File(['x'], 'a.py')] } });
    fireEvent.click(screen.getByRole('button', { name: '载入开发示例' }));
    const fresh = screen.getByLabelText('选择文件（优先于粘贴内容）') as HTMLInputElement;
    expect(fresh).not.toBe(input);
    expect(fresh.files?.length ?? 0).toBe(0);
  });
});
