import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Node.js에서 import를 쓸 때 현재 폴더 경로(__dirname)를 구하는 표준 방식
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

app.post('/api/analyze', (req, res) => {
  const { url } = req.body;

  try {
    const jsonPath = path.join(__dirname, 'data', 'result.json');
    
    if (!fs.existsSync(jsonPath)) {
      return res.status(444).json({ error: "검사 결과 파일이 존재하지 않습니다." });
    }

    const rawData = fs.readFileSync(jsonPath, 'utf8');
    const resultData = JSON.parse(rawData);

    return res.json(resultData);

  } catch (error) {
    console.error("파일 읽기 에러:", error);
    return res.status(500).json({ error: "결과 파일을 처리하는 중 오류가 발생했습니다." });
  }
});

app.listen(5000, () => {
  console.log("백엔드 서버 실행 중: http://localhost:5000");
});