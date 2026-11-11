import { useLayoutEffect } from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import SourceLines from '../src/components/SourceLines';
import type { Mark } from '../src/components/SourceLines';

const content = Array.from({ length: 600 }, (_, i) => `line ${i + 1}`).join('\n');
const marks: Mark[] = [
  { start: 1, end: 1, kind: 'finding', id: 'first' },
  { start: 2, end: 2, kind: 'finding', id: 'middle' },
  { start: 600, end: 600, kind: 'finding', id: 'last' },
];

it('opens the next marked finding when navigation and activation arrive in one burst', () => {
  const activate = vi.fn();
  render(<SourceLines label="burst source" content={content} marks={marks} focusLine={2} onActivate={activate} />);
  const region = screen.getByRole('group', { name: 'burst source' });
  act(() => {
    fireEvent.keyDown(region, { key: 'n' });
    fireEvent.keyDown(region, { key: 'Enter' });
  });
  expect(activate).toHaveBeenCalledWith(expect.objectContaining({ id: 'last' }));
});

it('returns to the controlled line when the parent asks for the same line again (focusKey)', () => {
  const props = { label: 'refocus source', content, marks };
  const { rerender } = render(<SourceLines {...props} focusLine={2} focusKey={1} />);
  const region = screen.getByRole('group', { name: 'refocus source' });
  fireEvent.keyDown(region, { key: 'n' });
  expect(screen.getByText('第 501–600 行，共 600 行')).toBeInTheDocument();
  rerender(<SourceLines {...props} focusLine={2} focusKey={2} />);
  expect(document.querySelector('[data-line="2"]')).toHaveAttribute('aria-current', 'true');
  expect(screen.getByText('第 1–500 行，共 600 行')).toBeInTheDocument();
});

it('opens a multi-line mark from any of its lines, including one in another window', () => {
  const activate = vi.fn();
  const span: Mark[] = [{ start: 498, end: 502, kind: 'finding', id: 'span' }];
  render(<SourceLines label="span source" content={content} marks={span} focusLine={1} onActivate={activate} />);
  const region = screen.getByRole('group', { name: 'span source' });
  act(() => {
    fireEvent.keyDown(region, { key: 'End' });
    fireEvent.keyDown(region, { key: 'Home' });
    for (let i = 0; i < 500; i += 1) fireEvent.keyDown(region, { key: 'ArrowDown' }); // line 501
    fireEvent.keyDown(region, { key: 'Enter' });
  });
  expect(activate).toHaveBeenCalledWith(expect.objectContaining({ id: 'span' }));
});

it('uses the new controlled focus before passive effects when keyboard input follows a commit', () => {
  const activate = vi.fn();
  function Harness({ focus }: { focus: number }) {
    useLayoutEffect(() => {
      if (focus !== 600) return;
      const region = screen.getByRole('group', { name: 'controlled source' });
      region.dispatchEvent(new KeyboardEvent('keydown', { key: 'p', bubbles: true }));
      region.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    }, [focus]);
    return <SourceLines label="controlled source" content={content} marks={marks} focusLine={focus} onActivate={activate} />;
  }
  const { rerender } = render(<Harness focus={1} />);
  rerender(<Harness focus={600} />);
  expect(activate).toHaveBeenCalledWith(expect.objectContaining({ id: 'middle' }));
});
