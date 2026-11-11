import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent } from 'react';

export type MarkKind = 'finding' | 'selected' | 'target' | 'changed' | 'persisting' | 'preexisting' | 'introduced';
export interface Mark { start: number; end: number; kind: MarkKind; note?: string; id?: string }

export const MARK_TEXT: Record<MarkKind, string> = {
  finding: '检测发现', selected: '当前所选发现', target: '修复目标', changed: '改动',
  persisting: '仍存在', preexisting: '原有未修复', introduced: '新增风险',
};
const MAX_LINES = 500; // inputs are small; the cap only bounds the DOM for pathological one-character lines

const clamp = (value: number, total: number) => Math.min(Math.max(value, 1), Math.max(total, 1));
const valid = (mark: Mark, total: number) => mark.start >= 1 && mark.end >= mark.start && mark.start <= total;

/**
 * Plain-text source with line numbers. Content is rendered as React text only (never as HTML), marks are
 * conveyed by text tags as well as colour, and the whole block is keyboard operable:
 * ↑/↓ line, PageUp/PageDown 10 lines, Home/End, N/P next/previous marked line, Enter opens the mark.
 *
 * The cursor has one authority: a ref that every key handler reads and writes synchronously, so a burst of
 * keys inside one batch (or a key that arrives between a commit and its passive effects) always acts on the
 * position the previous key produced. The rendered cursor state only mirrors it. When the controlled focus
 * (focusLine/focusKey/content) changes, the cursor is reset during render, before any layout effect or
 * event handler of the same commit can observe a stale position.
 */
export default function SourceLines({ label, content, marks, focusLine, focusKey, onActivate }: {
  label: string; content: string; marks: Mark[]; focusLine?: number; focusKey?: number; onActivate?: (mark: Mark) => void;
}) {
  const lines = useMemo(() => {
    const rows = content.split('\n');
    if (rows.length > 1 && rows.at(-1) === '') rows.pop();
    return rows;
  }, [content]);
  const total = lines.length;
  const markedLines = useMemo(
    () => [...new Set(marks.filter(m => valid(m, total)).map(m => m.start))].sort((a, b) => a - b),
    [marks, total],
  );
  const initialCursor = () => clamp(focusLine ?? markedLines[0] ?? 1, total);

  const [cursor, setCursor] = useState(initialCursor);
  const [seen, setSeen] = useState({ content, focusLine, focusKey });
  if (seen.content !== content || seen.focusLine !== focusLine || seen.focusKey !== focusKey) {
    setSeen({ content, focusLine, focusKey });
    setCursor(initialCursor());
  }
  const bounded = clamp(cursor, total);
  const cursorRef = useRef(bounded);
  // Layout effects of this component run before those of its parents, so a parent that reacts to the
  // same commit (and dispatches keys) already sees the new position.
  useLayoutEffect(() => { cursorRef.current = bounded; }, [bounded]);

  const windowStart = Math.floor((bounded - 1) / MAX_LINES) * MAX_LINES;
  const windowEnd = Math.min(windowStart + MAX_LINES, total);
  const byLine = useMemo(() => {
    const map = new Map<number, Mark[]>();
    for (const mark of marks) {
      if (!valid(mark, total)) continue;
      for (let line = Math.max(mark.start, windowStart + 1); line <= Math.min(mark.end, windowEnd); line += 1) {
        map.set(line, [...(map.get(line) ?? []), mark]);
      }
    }
    return map;
  }, [marks, total, windowStart, windowEnd]);
  const host = useRef<HTMLDivElement>(null);
  const identity = useRef(`src-${Math.random().toString(36).slice(2, 8)}`).current;

  useEffect(() => {
    host.current?.querySelector<HTMLElement>(`[data-line="${bounded}"]`)?.scrollIntoView?.({ block: 'nearest' });
  }, [bounded, focusKey]);

  function move(next: number) {
    const value = clamp(next, total);
    cursorRef.current = value; // authoritative immediately; state only drives rendering
    setCursor(value);
  }
  const marksAt = (line: number) => marks.filter(m => valid(m, total) && m.start <= line && line <= m.end);
  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const at = () => cursorRef.current;
    const keys: Record<string, () => void> = {
      ArrowDown: () => move(at() + 1), ArrowUp: () => move(at() - 1),
      PageDown: () => move(at() + 10), PageUp: () => move(at() - 10),
      Home: () => move(1), End: () => move(total),
      n: () => { const next = markedLines.find(line => line > at()); if (next) move(next); },
      p: () => { const previous = [...markedLines].reverse().find(line => line < at()); if (previous) move(previous); },
      // Looked up over all marks, not only the rendered window: the cursor may have just crossed a window.
      Enter: () => { const mark = marksAt(at())[0]; if (mark) onActivate?.(mark); },
    };
    const handler = keys[event.key];
    if (!handler || event.ctrlKey || event.metaKey || event.altKey) return;
    event.preventDefault(); handler();
  }

  return <><div className="ingest-actions"><button disabled={windowStart === 0} onClick={() => move(windowStart - MAX_LINES + 1)}>上一段源码 · {label}</button><span aria-live="polite">第 {windowStart + 1}–{windowEnd} 行，共 {total} 行</span><button disabled={windowEnd === total} onClick={() => move(windowEnd + 1)}>下一段源码 · {label}</button></div><div className="source-lines" ref={host} role="group" tabIndex={0} aria-label={label}
    aria-describedby={`${identity}-help`} aria-activedescendant={`${identity}-${bounded}`} onKeyDown={onKeyDown}>
    <p className="source-help" id={`${identity}-help`}>↑↓ 移动，N / P 跳到下一处 / 上一处标记，Enter 查看标记；共 {total} 行，{markedLines.length} 行有标记。</p>
    {lines.slice(windowStart, windowEnd).map((text, index) => {
      const number = windowStart + index + 1;
      const here = byLine.get(number) ?? [];
      const kinds = [...new Set(here.map(mark => mark.kind))];
      return <div key={number} id={`${identity}-${number}`} data-line={number}
        className={`source-line${kinds.map(kind => ` mark-${kind}`).join('')}${number === bounded ? ' cursor' : ''}`}
        aria-current={number === bounded ? 'true' : undefined} onClick={() => move(number)}>
        <span className="line-no" aria-hidden="true">{number}</span>
        <code>{text === '' ? ' ' : text}</code>
        {kinds.length > 0 && <span className="line-tags">{kinds.map(kind => {
          const note = here.find(mark => mark.kind === kind)?.note;
          return <span className="mark-tag" key={kind}>{MARK_TEXT[kind]}{note ? ` · ${note}` : ''}</span>;
        })}</span>}
      </div>;
    })}
  </div></>;
}
