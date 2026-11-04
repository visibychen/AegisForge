import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from '../src/App';
import { ApiError, getCapabilities, getHealth } from '../src/api/client';

vi.mock('../src/api/client', async importOriginal => {
  const original = await importOriginal<typeof import('../src/api/client')>();
  return { ...original, getHealth: vi.fn(), getCapabilities: vi.fn() };
});

beforeEach(() => { vi.mocked(getHealth).mockResolvedValue({ status: 'ok', request_id: 'test' }); });

describe('workspace foundation', () => {
  it('shows the current capability boundary without fabricated detection results', async () => {
    render(<App />);
    expect(screen.getByRole('heading', { name: '代码安全工作台' })).toBeInTheDocument();
    expect(screen.getByText(/漏洞检测与修复功能尚未开放/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /连接服务/ })).toBeDisabled();
    await screen.findByText('本地服务在线');
    expect(getCapabilities).not.toHaveBeenCalled();
  });

  it('connects explicitly and clears the token without storing it', async () => {
    vi.mocked(getCapabilities).mockResolvedValue({
      request_id: 'test', version: '0.1.0.dev1', stage: 'M1', model_mode: 'fake',
      analysis_available: false, repair_available: false, dynamic_validation_available: false,
      supported_input_types: [], planned_input_types: ['source', 'http'],
      max_file_bytes: 2097152, max_files: 10, max_total_bytes: 10485760,
    });
    render(<App />);
    fireEvent.change(screen.getByLabelText('访问令牌'), { target: { value: 'local-test-token' } });
    fireEvent.click(screen.getByRole('button', { name: /连接服务/ }));
    await screen.findByText('已连接本地服务');
    expect(getCapabilities).toHaveBeenCalledWith('local-test-token');
    expect(screen.getByLabelText('访问令牌')).toHaveValue('');
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(screen.getByText(/真实模型尚未接入/)).toBeInTheDocument();
  });

  it('reports a rejected token and never shows a successful connection', async () => {
    vi.mocked(getCapabilities).mockRejectedValue(new ApiError('访问令牌无效或缺失。'));
    render(<App />);
    fireEvent.change(screen.getByLabelText('访问令牌'), { target: { value: 'incorrect' } });
    fireEvent.click(screen.getByRole('button', { name: /连接服务/ }));
    await screen.findByText('访问令牌无效或缺失。');
    await waitFor(() => expect(screen.queryByText('已连接本地服务')).not.toBeInTheDocument());
  });

  it('lets the user pause decorative motion without persisting anything', async () => {
    const { container } = render(<App />);
    const toggle = screen.getByRole('button', { name: '动态效果' });
    expect(toggle).toHaveAttribute('aria-pressed', 'true');
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute('aria-pressed', 'false');
    expect(container.querySelector('.app-shell')).not.toHaveClass('motion-on');
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute('aria-pressed', 'true');
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    await screen.findByText('本地服务在线');
  });

  it('never lets the toggle override a system reduced-motion preference', async () => {
    const original = window.matchMedia;
    window.matchMedia = (query: string) => ({
      matches: query.includes('reduce'), media: query, onchange: null,
      addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {},
      dispatchEvent() { return false; },
    }) as unknown as MediaQueryList;
    try {
      render(<App />);
      const toggle = screen.getByRole('button', { name: '动态效果' });
      expect(toggle).toHaveAttribute('aria-pressed', 'false');
      expect(toggle).toHaveAttribute('aria-disabled', 'true');
      expect(toggle).toHaveAccessibleDescription(/系统已设置减少动态效果/);
      fireEvent.click(toggle);
      expect(toggle).toHaveAttribute('aria-pressed', 'false');
      await screen.findByText('本地服务在线');
    } finally {
      window.matchMedia = original;
    }
  });

  it('keeps the workspace visible when the backend is offline', async () => {
    vi.mocked(getHealth).mockRejectedValue(new TypeError('offline'));
    render(<App />);
    await screen.findByText('后端尚未连接');
    expect(screen.getByRole('heading', { name: '代码安全工作台' })).toBeInTheDocument();
  });
});
