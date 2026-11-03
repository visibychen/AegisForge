import React from 'react';
import ReactDOM from 'react-dom/client';
import { ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import App from './App';
import './styles.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider locale={zhCN} theme={{
      token: {
        colorPrimary: '#157c68', colorInfo: '#157c68', borderRadius: 10,
        fontFamily: 'Inter, "Segoe UI", "Microsoft YaHei", sans-serif',
      },
    }}>
      <App />
    </ConfigProvider>
  </React.StrictMode>,
);
