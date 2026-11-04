import { useEffect, useState } from 'react';
import { ThunderboltOutlined } from '@ant-design/icons';

const REDUCED_MOTION_QUERY = '(prefers-reduced-motion: reduce)';

// Tracks the OS-level preference live; the CSS media query enforces it independently of this hook.
export function useSystemReducedMotion() {
  const supported = typeof window.matchMedia === 'function';
  const [reduced, setReduced] = useState(() => supported && window.matchMedia(REDUCED_MOTION_QUERY).matches);
  useEffect(() => {
    if (!supported) return;
    const query = window.matchMedia(REDUCED_MOTION_QUERY);
    const update = () => setReduced(query.matches);
    update();
    query.addEventListener('change', update);
    return () => query.removeEventListener('change', update);
  }, [supported]);
  return reduced;
}

interface MotionToggleProps {
  enabled: boolean;
  systemReduced: boolean;
  onChange: (enabled: boolean) => void;
}

// The user may pause decorative motion, but can never re-enable it over a system reduce preference.
export default function MotionToggle({ enabled, systemReduced, onChange }: MotionToggleProps) {
  const active = enabled && !systemReduced;
  return (
    <>
      <button type="button" className="motion-toggle" aria-pressed={active} aria-disabled={systemReduced || undefined}
        aria-describedby={systemReduced ? 'motion-hint' : undefined}
        title={systemReduced ? '系统已设置减少动态效果' : active ? '暂停装饰动画' : '恢复装饰动画'}
        onClick={() => { if (!systemReduced) onChange(!enabled); }}>
        <ThunderboltOutlined aria-hidden="true" />
        <span className="motion-label">动态效果</span>
        <span className="motion-track" aria-hidden="true" />
      </button>
      {systemReduced && <span id="motion-hint" className="visually-hidden">系统已设置减少动态效果，装饰动画保持关闭。</span>}
    </>
  );
}
