import React from 'react'
import ReactDOM from 'react-dom/client'

// 피그마 메인 화면 파일 직접 연결
import App from './app/App'

// 피그마 전용 스타일 로드
import './styles/globals.css'
import './styles/tailwind.css'
import './styles/theme.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)