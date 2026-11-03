import { useEffect, useState } from 'react';
import {
  ArrowRightOutlined, CheckCircleOutlined, CodeOutlined, DashboardOutlined,
  FileSearchOutlined, HistoryOutlined, SafetyCertificateOutlined, SettingOutlined,
  ThunderboltOutlined, ToolOutlined,
} from '@ant-design/icons';
import { Alert, Button, Input, Tag } from 'antd';
import { ApiError, getCapabilities, getHealth } from './api/client';
import type { Capabilities } from './types/api';

const workflow = [
  { step: '01', title: '提交待检内容', detail: '源码文件 · HTTP 请求文本', icon: <CodeOutlined /> },
  { step: '02', title: '定位安全风险', detail: '规则特征 · 模型分析 · 证据定位', icon: <FileSearchOutlined /> },
  { step: '03', title: '生成修复方案', detail: '候选代码 · 差异对比', icon: <ToolOutlined /> },
  { step: '04', title: '验证修复结果', detail: '安全回归 · 功能验证', icon: <SafetyCertificateOutlined /> },
];

export default function App() {
  const [health, setHealth] = useState<'loading' | 'ok' | 'offline'>('loading');
  const [token, setToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [capabilities, setCapabilities] = useState<Capabilities | null>(null);
  const [error, setError] = useState('');

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
    <div className="app-shell">
      <aside className="sidebar" aria-label="主导航">
        <a href="#workspace" className="brand">
          <span className="brand-mark"><SafetyCertificateOutlined /></span>
          <span><strong>AegisForge</strong><small>铸盾 · 代码安全</small></span>
        </a>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          <a href="#workspace" className="nav-item active" aria-current="page"><DashboardOutlined />工作台</a>
          <span className="nav-item unavailable" aria-disabled="true"><FileSearchOutlined />检测任务<span>即将开放</span></span>
          <span className="nav-item unavailable" aria-disabled="true"><ToolOutlined />修复工作台</span>
          <span className="nav-item unavailable" aria-disabled="true"><HistoryOutlined />历史记录</span>
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-note"><span className="small-dot" />本地安全工作空间</div>
          <p>发现风险，修复缺陷。<br />让每一次改动更有依据。</p>
          <span className="build-label">FOUNDATION PREVIEW</span>
        </div>
      </aside>

      <div className="main-shell" id="workspace">
        <header className="topbar">
          <span className="breadcrumb">工作空间 <span>/</span> <strong>总览</strong></span>
          <div className="topbar-status">
            <span className={`status-dot ${health}`} />
            <span role="status">{health === 'loading' ? '正在检查服务' : health === 'ok' ? '本地服务在线' : '后端尚未连接'}</span>
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
            <div className="hero-copy">
              <span className="hero-kicker"><ThunderboltOutlined /> 智能分析 · 证据驱动</span>
              <h2 id="hero-title">洞察代码风险，<br /><span>构筑安全防线。</span></h2>
              <p>计划支持 Python Web 源码与 HTTP 请求文本，<br className="desktop-break" />围绕 XSS、SQL 注入和命令执行风险提供分析与修复。</p>
              <div className="hero-tags"><span>漏洞检测</span><i /><span>补丁生成</span><i /><span>修复验证</span></div>
            </div>
            <div className="hero-visual" aria-hidden="true">
              <div className="orbit orbit-one" /><div className="orbit orbit-two" />
              <div className="shield-core"><SafetyCertificateOutlined /></div>
              <span className="visual-label label-top"><CodeOutlined /> Code insight</span>
              <span className="visual-label label-bottom"><CheckCircleOutlined /> Verified changes</span>
            </div>
          </section>

          <section className="risk-grid" aria-label="计划覆盖的风险类型">
            {[
              ['XSS', '跨站脚本', '追踪不可信输入与页面输出', '79'],
              ['SQL Injection', 'SQL 注入', '识别输入拼接与查询边界风险', '89'],
              ['Command Injection', '命令注入', '关注危险调用与外部参数传递', '78'],
            ].map(([name, label, description, cwe]) => (
              <article className="risk-card" key={cwe}><span className="risk-icon"><CodeOutlined /></span><span className="cwe">CWE-{cwe}</span><h3>{label}<small>{name}</small></h3><p>{description}</p><span className="planned-badge">计划支持</span></article>
            ))}
          </section>

          <div className="bottom-grid">
            <section className="surface workflow-panel" aria-labelledby="workflow-title">
              <div className="section-heading"><h2 id="workflow-title">分析与修复流程</h2><span>完整流程规划</span></div>
              <div className="workflow-list">{workflow.map(item => (
                <div className="workflow-item" key={item.step}><span className="step-number">{item.step}</span><span className="step-icon">{item.icon}</span><div><h3>{item.title}</h3><p>{item.detail}</p></div><ArrowRightOutlined className="step-arrow" /></div>
              ))}</div>
              <p className="boundary-note">HTTP 请求中的攻击特征仅提示潜在风险，服务端漏洞需要结合源码与验证证据判断。</p>
            </section>

            <section className="surface connection-panel" aria-labelledby="connection-title">
              <div className="section-heading"><h2 id="connection-title"><SettingOutlined /> 服务连接</h2></div>
              <p className="connection-intro">使用本地配置中的访问令牌，查看当前服务能力。</p>
              <form onSubmit={event => { event.preventDefault(); void connect(); }}>
                <label htmlFor="api-token">访问令牌</label>
                <Input.Password id="api-token" value={token} onChange={event => setToken(event.target.value)} placeholder="输入本地访问令牌" autoComplete="off" />
                <Button htmlType="submit" type="primary" block loading={loading} disabled={!token.trim()} icon={<ArrowRightOutlined />}>连接服务</Button>
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
