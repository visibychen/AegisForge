import { render, screen, fireEvent } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import SourceLines from '../src/components/SourceLines';

it('shows the selected evidence beyond line 2000 without renumbering it', async () => {
  render(<SourceLines label="long source" content={'\n'.repeat(2500) + 'os.system(user)\n'}
    marks={[{ start: 2501, end: 2501, kind: 'selected' }]} focusLine={2501} />);
  expect(await screen.findByText('os.system(user)')).toBeInTheDocument();
  expect(document.querySelector('[data-line="2501"]')).toHaveClass('mark-selected');
});

it('crosses windows with absolute keyboard positions and ignores a phantom trailing line', () => {
  const picked = vi.fn();
  render(<SourceLines label="keyboard source" content={Array.from({length: 600}, (_, i) => `line ${i+1}`).join('\n')+'\n'}
    marks={[{ start:600, end:600, kind:'finding', id:'last' }]} focusLine={500} onActivate={picked} />);
  const host = screen.getByRole('group', {name:'keyboard source'});
  fireEvent.keyDown(host, {key:'ArrowDown'});
  expect(document.querySelector('[data-line="501"]')).toHaveAttribute('aria-current','true');
  expect(document.querySelectorAll('.source-line.cursor')).toHaveLength(1);
  fireEvent.keyDown(host, {key:'n'});
  fireEvent.keyDown(host, {key:'Enter'});
  expect(picked).toHaveBeenCalledWith(expect.objectContaining({id:'last'}));
  fireEvent.keyDown(host, {key:'End'});
  expect(document.querySelector('[data-line="600"]')).toHaveAttribute('aria-current','true');
  expect(document.querySelector('[data-line="601"]')).toBeNull();
});
