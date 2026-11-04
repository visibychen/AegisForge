import { CheckCircleOutlined, CodeOutlined } from '@ant-design/icons';

// Decorative shield console: rotating rings, radar sweep and an energy trace on the shield outline.
// Pure SVG/CSS so it needs no network assets; all motion is disabled under prefers-reduced-motion.
export default function HeroVisual() {
  return (
    <div className="hero-visual" aria-hidden="true">
      <div className="radar-sweep" />
      <svg className="hero-svg" viewBox="0 0 320 320" focusable="false">
        <defs>
          <linearGradient id="af-energy" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#67e8f9" />
            <stop offset=".55" stopColor="#38bdf8" />
            <stop offset="1" stopColor="#818cf8" />
          </linearGradient>
          <radialGradient id="af-core">
            <stop offset="0" stopColor="#22d3ee" stopOpacity=".3" />
            <stop offset="1" stopColor="#22d3ee" stopOpacity="0" />
          </radialGradient>
        </defs>
        <circle className="core-glow" cx="160" cy="160" r="120" fill="url(#af-core)" />
        <g className="ring ring-outer">
          <circle className="ring-dash" cx="160" cy="160" r="148" />
          <circle className="ring-halo" cx="160" cy="12" r="7" />
          <circle className="ring-node" cx="160" cy="12" r="3" />
        </g>
        <g className="ring ring-mid">
          <circle className="ring-arc" cx="160" cy="160" r="120" pathLength="100" />
          <circle className="ring-halo" cx="280" cy="160" r="6" />
          <circle className="ring-node" cx="280" cy="160" r="2.5" />
        </g>
        <g className="ring ring-inner">
          <circle className="ring-tick" cx="160" cy="160" r="94" />
        </g>
        <path className="shield-base" d="M160 97 L211 118 V160 C211 190 187 211 160 223 C133 211 109 190 109 160 V118 Z" />
        <path className="shield-trace" pathLength="100" d="M160 97 L211 118 V160 C211 190 187 211 160 223 C133 211 109 190 109 160 V118 Z" />
        <path className="shield-check" d="M136 160 L154 178 L190 136" />
      </svg>
      <span className="visual-label label-top"><CodeOutlined /> SOURCE · HTTP</span>
      <span className="visual-label label-bottom"><CheckCircleOutlined /> DIFF · VERIFY</span>
    </div>
  );
}
