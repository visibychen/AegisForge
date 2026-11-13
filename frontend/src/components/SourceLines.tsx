import { useEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent } from 'react';

export type MarkKind = 'finding' | 'selected' | 'target' | 'changed' | 'persisting' | 'preexisting' | 'introduced';
export interface Mark { start: number; end: number; kind: MarkKind; note?: string; id?: string }

export const MARK_TEXT: Record<MarkKind, string> = {
  finding: '检测发现', selected: '当前所选发现', target: '修复目标', changed: '改动',
  persisting: '仍存在', preexisting: '原有未修复', introduced: '新增风险',
};
const MAX_LINES = 500; // inputs are small; the cap only bounds the DOM for pathological one-character lines

/**
 * Plain-text source with line numbers. Content is rendered as React text only (never as HTML), marks are
 * conveyed by text tags as well as colour, and the whole block is keyboard operable:
 * ↑/↓ line, PageUp/PageDown 10 lines, Home/End, N/P next/previous marked line, Enter opens the mark.
 */
export default function SourceLines({ label, content, marks, focusLine, focusKey, onActivate }: {
  label: string; content: string; marks: Mark[]; focusLine?: number; focusKey?: number; onActivate?: (mark: Mark) => void;
}) {
  const lines = useMemo(() => {
    const rows = content.split('\n');
    if (rows.length > 1 && rows.at(-1) === '') rows.pop();
    return rows;
  }, [content]);
  const [cursor, setCursor] = useState(() => Math.min(Math.max(focusLine ?? 1, 1), lines.length));
  const bounded = Math.min(Math.max(cursor, 1), lines.length);
  const windowStart = Math.floor((bounded - 1) / MAX_LINES) * MAX_LINES;
  const windowEnd = Math.min(windowStart + MAX_LINES, lines.length);

  const byLine = useMemo(() => {
    const map = new Map<number, Mark[]>();
    for (const mark of marks) {
      if (mark.start < 1 || mark.end < mark.start || mark.start > lines.length) continue;
      for (let line = Math.max(mark.start, windowStart + 1); line <= Math.min(mark.end, windowEnd); line += 1) {
        map.set(line, [...(map.get(line) ?? []), mark]);
      }
    }
    return map;
  }, [marks, windowStart, windowEnd]);
  const markedLines = useMemo(() => [...new Set(marks.filter(m => m.start >= 1 && m.start <= lines.length && m.end >= m.start).map(m => m.start))].sort((a, b) => a - b), [marks, lines.length]);
  const host = useRef<HTMLDivElement>(null);
  const identity = useRef(`src-${Math.random().toString(36).slice(2, 8)}`).current;

  useEffect(() => {
    setCursor(Math.min(Math.max(focusLine ?? markedLines[0] ?? 1, 1), lines.length));
  }, [focusLine, content, focusKey]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    host.current?.querySelector<HTMLElement>(`[data-line="${cursor}"]`)?.scrollIntoView?.({ block: 'nearest' });
  }, [cursor, focusKey]);

  function move(next: number) { setCursor(Math.min(Math.max(next, 1), lines.length)); }
  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const keys: Record<string, () => void> = {
      ArrowDown: () => move(cursor + 1), ArrowUp: () => move(cursor - 1),
      PageDown: () => move(cursor + 10), PageUp: () => move(cursor - 10),
      Home: () => move(1), End: () => move(lines.length),
      n: () => { const next = markedLines.find(line => line > cursor); if (next) move(next); },
      p: () => { const previous = [...markedLines].reverse().find(line => line < cursor); if (previous) move(previous); },
      Enter: () => { const mark = byLine.get(cursor)?.[0]; if (mark) onActivate?.(mark); },
    };
    const handler = keys[event.key];
    if (!handler || event.ctrlKey || event.metaKey || event.altKey) return;
    event.preventDefault(); handler();
  }

  return <><div className="ingest-actions"><button disabled={windowStart === 0} onClick={() => move(windowStart - MAX_LINES + 1)}>上一段源码 · {label}</button><span aria-live="polite">第 {windowStart + 1}–{windowEnd} 行，共 {lines.length} 行</span><button disabled={windowEnd === lines.length} onClick={() => move(windowEnd + 1)}>下一段源码 · {label}</button></div><div className="source-lines" ref={host} role="group" tabIndex={0} aria-label={label}
    aria-describedby={`${identity}-help`} aria-activedescendant={`${identity}-${cursor}`} onKeyDown={onKeyDown}>
    <p className="source-help" id={`${identity}-help`}>↑↓ 移动，N / P 跳到下一处 / 上一处标记，Enter 查看标记；共 {lines.length} 行，{markedLines.length} 行有标记。</p>
    {lines.slice(windowStart, windowEnd).map((text, index) => {
      const number = windowStart + index + 1;
      const here = byLine.get(number) ?? [];
      const kinds = [...new Set(here.map(mark => mark.kind))];
      return <div key={number} id={`${identity}-${number}`} data-line={number}
        className={`source-line${kinds.map(kind => ` mark-${kind}`).join('')}${number === cursor ? ' cursor' : ''}`}
        aria-current={number === cursor ? 'true' : undefined} onClick={() => setCursor(number)}>
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
