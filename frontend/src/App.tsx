import { useEffect, useState } from 'react';
import {
  ApiOutlined, ArrowRightOutlined, CheckCircleOutlined, CodeOutlined, DashboardOutlined, DatabaseOutlined,
  FileSearchOutlined, HistoryOutlined, Html5Outlined, LockOutlined, SafetyCertificateOutlined, ToolOutlined,
} from '@ant-design/icons';
import { Alert, Button, Input, Tag } from 'antd';
import { ApiError, getCapabilities, getHealth } from './api/client';
import HeroVisual from './components/HeroVisual';
import MotionToggle, { useSystemReducedMotion } from './components/MotionToggle';
import type { Capabilities } from './types/api';

const workflow = [
  { step: '01', title: '提交待检内容', detail: '源码文件 · HTTP 请求文本', icon: <CodeOutlined /> },
  { step: '02', title: '定位安全风险', detail: '规则特征 · 模型分析 · 证据定位', icon: <FileSearchOutlined /> },
  { step: '03', title: '生成修复方案', detail: '候选代码 · 差异对比', icon: <ToolOutlined /> },
  { step: '04', title: '验证修复结果', detail: '安全回归 · 功能验证', icon: <SafetyCertificateOutlined /> },
];

const risks = [
  { name: 'XSS', label: '跨站脚本', description: '追踪不可信输入与页面输出', cwe: '79', tone: 'cyan', icon: <Html5Outlined /> },
  { name: 'SQL Injection', label: 'SQL 注入', description: '识别输入拼接与查询边界风险', cwe: '89', tone: 'sky', icon: <DatabaseOutlined /> },
  { name: 'Command Injection', label: '命令注入', description: '关注危险调用与外部参数传递', cwe: '78', tone: 'violet', icon: <CodeOutlined /> },
];

export default function App() {
  const [health, setHealth] = useState<'loading' | 'ok' | 'offline'>('loading');
  const [token, setToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [capabilities, setCapabilities] = useState<Capabilities | null>(null);
  const [error, setError] = useState('');
  const [motionEnabled, setMotionEnabled] = useState(true); // In-memory only; resets on reload.
  const systemReducedMotion = useSystemReducedMotion();

  useEffect(() => {
    let active = true;
    getHealth().then(() => { if (active) setHealth('ok'); })
      .catch(() => { if (active) setHealth('offline'); });
    return () => { active = false; };
  }, []);

  async function connect() {
    setLoading(true);
    setError('');
    setCapabilities(null);
    try {
      const response = await getCapabilities(token.trim());
      setCapabilities(response);
      setToken(''); // Keep the shared token out of persistent browser storage.
    } catch (exception) {
      setError(exception instanceof ApiError ? exception.message : '无法连接服务，请确认后端已启动。');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className={`app-shell${motionEnabled ? ' motion-on' : ''}`}>
      <div className="backdrop" aria-hidden="true"><div className="backdrop-grid" /><div className="aurora aurora-a" /><div className="aurora aurora-b" /></div>

      <aside className="sidebar" aria-label="主导航">
        <a href="#workspace" className="brand">
          <span className="brand-mark"><SafetyCertificateOutlined /></span>
          <span className="brand-text"><strong>AegisForge</strong><small>铸盾 · 代码安全</small></span>
        </a>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          <a href="#workspace" className="nav-item active" aria-current="page" title="工作台"><DashboardOutlined /><span className="nav-text">工作台</span></a>
          <span className="nav-item unavailable" aria-disabled="true" title="检测任务（即将开放）"><FileSearchOutlined /><span className="nav-text">检测任务</span><span className="nav-soon">即将开放</span></span>
          <span className="nav-item unavailable" aria-disabled="true" title="修复工作台（未开放）"><ToolOutlined /><span className="nav-text">修复工作台</span></span>
          <span className="nav-item unavailable" aria-disabled="true" title="历史记录（未开放）"><HistoryOutlined /><span className="nav-text">历史记录</span></span>
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-note"><span className="small-dot" />本地安全工作空间</div>
          <p>发现风险，修复缺陷。<br />让每一次改动更有依据。</p>
          <span className="build-label">FOUNDATION PREVIEW</span>
        </div>
      </aside>

      <div className="main-shell" id="workspace">
        <header className="topbar">
          <a href="#workspace" className="topbar-brand"><SafetyCertificateOutlined /><strong>AegisForge</strong></a>
          <span className="breadcrumb">工作空间 <span>/</span> <strong>总览</strong></span>
          <div className="topbar-status">
            <MotionToggle enabled={motionEnabled} systemReduced={systemReducedMotion} onChange={setMotionEnabled} />
            <span className={`status-pill ${health}`}>
              <span className={`status-dot ${health}`} />
              <span role="status">{health === 'loading' ? '正在检查服务' : health === 'ok' ? '本地服务在线' : '后端尚未连接'}</span>
            </span>
            <span className="avatar">AF</span>
          </div>
        </header>

        <main>
          <section className="page-heading">
            <div><div className="eyebrow">CODE SECURITY WORKSPACE</div><h1>代码安全工作台</h1><p>从风险发现到修复验证，让安全分析有迹可循。</p></div>
            <Tag className="preview-tag">基础预览</Tag>
          </section>

          <Alert type="info" showIcon className="preview-alert"
            title="当前可查看工作台并连接本地服务，漏洞检测与修复功能尚未开放。" />

          <section className="hero-panel" aria-labelledby="hero-title">
            <div className="hero-streams" aria-hidden="true"><span /><span /><span /></div>
            <div className="hero-copy">
              <span className="hero-kicker"><span className="kicker-dot" />智能分析 · 证据驱动</span>
              <h2 id="hero-title">洞察代码风险，<br /><span>构筑安全防线。</span></h2>
              <p>计划支持 Python Web 源码与 HTTP 请求文本，<br className="desktop-break" />围绕 XSS、SQL 注入和命令执行风险提供分析与修复。</p>
              <div className="hero-flow"><span>漏洞检测</span><i className="flow-link" /><span>补丁生成</span><i className="flow-link" /><span>修复验证</span></div>
            </div>
            <HeroVisual />
          </section>

          <section className="risk-grid" aria-label="计划覆盖的风险类型">
            {risks.map(risk => (
              <article className={`risk-card tone-${risk.tone}`} key={risk.cwe}>
                <div className="risk-head"><span className="risk-icon">{risk.icon}</span><span className="cwe">CWE-{risk.cwe}</span></div>
                <h3>{risk.label}<small>{risk.name}</small></h3>
                <p>{risk.description}</p>
                <span className="planned-badge">计划支持</span>
              </article>
            ))}
          </section>

          <div className="bottom-grid">
            <section className="surface workflow-panel" aria-labelledby="workflow-title">
              <div className="section-heading"><h2 id="workflow-title">分析与修复流程</h2><span>完整流程规划</span></div>
              <div className="workflow-list">{workflow.map(item => (
                <div className="workflow-item" key={item.step}><span className="step-icon">{item.icon}</span><div><h3>{item.title}</h3><p>{item.detail}</p></div><span className="step-number">{item.step}</span></div>
              ))}</div>
              <p className="boundary-note">HTTP 请求中的攻击特征仅提示潜在风险，服务端漏洞需要结合源码与验证证据判断。</p>
            </section>

            <section className="surface connection-panel" aria-labelledby="connection-title">
              <div className="section-heading"><h2 id="connection-title"><ApiOutlined /> 服务连接</h2><span className="session-chip"><LockOutlined aria-hidden="true" />仅限当前会话</span></div>
              <p className="connection-intro">使用本地配置中的访问令牌，查看当前服务能力。</p>
              <form onSubmit={event => { event.preventDefault(); void connect(); }}>
                <label htmlFor="api-token">访问令牌</label>
                <Input.Password id="api-token" value={token} onChange={event => setToken(event.target.value)} placeholder="输入本地访问令牌" autoComplete="off" />
                <Button className="connect-button" htmlType="submit" type="primary" block loading={loading} disabled={!token.trim()} icon={<ArrowRightOutlined />}>连接服务</Button>
              </form>
              {error && <Alert type="error" showIcon title={error} role="alert" />}
              {capabilities && <div className="connected-state" role="status"><CheckCircleOutlined /><div><strong>已连接本地服务</strong><p>模拟模式 · 真实模型尚未接入</p><p>漏洞检测与修复尚未开放。</p></div></div>}
              <div className="privacy-note"><SafetyCertificateOutlined />令牌仅用于当前连接，不保存到浏览器存储。</div>
            </section>
          </div>
          <footer>AegisForge 铸盾<span>面向代码安全的分析与修复工作空间</span></footer>
        </main>
      </div>
    </div>
  );
}
