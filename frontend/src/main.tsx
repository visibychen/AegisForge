import React from 'react';
import ReactDOM from 'react-dom/client';
import { ConfigProvider, theme } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import App from './App';
import './styles.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider locale={zhCN} theme={{
      algorithm: theme.darkAlgorithm,
      token: {
        colorPrimary: '#22d3ee', colorInfo: '#38bdf8', colorSuccess: '#34d399', borderRadius: 10,
        colorBgContainer: '#08142a', colorBorder: '#1f3a56', colorText: '#e6f0fb',
        fontFamily: 'Inter, "Segoe UI", "Microsoft YaHei", sans-serif',
      },
    }}>
      <App />
    </ConfigProvider>
  </React.StrictMode>,
);
