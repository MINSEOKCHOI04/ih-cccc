// 🚀 인증 서버 완성본 (중복 로그인 방지 + 2시간 TTL + 하트비트 유지)

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// 필요한 경우 프록시 환경에서만 주석 해제
// app.set('trust proxy', true);

// 세션 만료 시간 (2시간)
const SESSION_TTL_MS = 120 * 60 * 1000;

// email → { sessionId, ip, last }
const activeSessions = new Map();

// 시간 / IP 처리 함수
const nowKR = () => new Date().toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' });
const clientIP = (req) => {
  const xff = req.headers['x-forwarded-for'] || '';
  return (xff.split(',')[0] || '').trim() || req.connection.remoteAddress || '';
};

// 세션 만료 여부 정리
function pruneExpired(email) {
  const s = activeSessions.get(email);
  if (!s) return;
  if (Date.now() - s.last > SESSION_TTL_MS) activeSessions.delete(email);
}

// 기본 상태 확인
app.get('/', (_, res) => res.send('✅ 인증 서버가 실행 중입니다.'));

// ✅ 로그인 (이메일 기준 중복 로그인 방지)
app.all('/auth', (req, res) => {
  const usersPath = path.join(__dirname, 'users.json');
  if (!fs.existsSync(usersPath)) return res.json({ ok: false, msg: 'users.json 파일 없음' });

  const users = JSON.parse(fs.readFileSync(usersPath, 'utf-8'));
  const q = req.method === 'GET' ? req.query : req.body;
  const email = String(q.email || '').trim();
  const code = String(q.code || '').trim();
  const ip = clientIP(req);
  const time = nowKR();

  if (!email || !code)
    return res.json({ ok: false, msg: 'email, code 필요' });

  // 유효한 계정 확인
  if (!users[email] || users[email] !== code) {
    console.log(`[로그인 실패] 🔴 ${time} | ${email} | IP:${ip}`);
    return res.json({ ok: false, msg: '아이디 또는 비밀번호가 올바르지 않습니다.' });
  }

  pruneExpired(email);

  // ✅ 중복 로그인 발생 시 기존 세션 삭제 (기존 로그인 즉시 종료)
  const cur = activeSessions.get(email);
  if (cur) {
    console.log(`[중복 로그인 감지 → 기존 세션 종료] 🔁 ${time} | ${email} | IP:${ip}`);
    activeSessions.delete(email);
  }

  // ✅ 새 세션 생성
  const sessionId = 'sess_' + crypto.randomBytes(8).toString('hex');
  activeSessions.set(email, { sessionId, ip, last: Date.now() });
  console.log(`[로그인 성공] 🟢 ${time} | ${email} | IP:${ip}`);

  return res.json({ ok: true, sessionId, ttlMs: SESSION_TTL_MS });
});

// ✅ 세션 확인
app.get('/check', (req, res) => {
  const email = String(req.query.email || '').trim();
  if (!email) return res.json({ ok: false, msg: 'email 필요' });

  pruneExpired(email);
  const cur = activeSessions.get(email);

  if (!cur) return res.json({ ok: false, expired: true });

  const valid = Date.now() - cur.last <= SESSION_TTL_MS;
  if (!valid) {
    activeSessions.delete(email);
    return res.json({ ok: false, expired: true });
  }

  return res.json({
    ok: true,
    sessionId: cur.sessionId,
    expiresInMs: SESSION_TTL_MS - (Date.now() - cur.last)
  });
});

// ✅ 하트비트 (세션 유지)
app.post('/touch', (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.json({ ok: false, msg: 'email 필요' });

  const cur = activeSessions.get(email);
  if (!cur) return res.json({ ok: false, expired: true });

  cur.last = Date.now();
  return res.json({ ok: true });
});

// ✅ 로그아웃
app.all('/logout', (req, res) => {
  const q = req.method === 'GET' ? req.query : req.body;
  const email = String(q.email || '').trim();
  if (!email) return res.json({ ok: false, msg: 'email 필요' });

  if (activeSessions.has(email)) {
    activeSessions.delete(email);
    console.log(`[로그아웃] 🔓 ${nowKR()} | ${email}`);
    return res.json({ ok: true, msg: '로그아웃 완료' });
  }

  return res.json({ ok: false, msg: '이미 로그아웃 상태' });
});

// ✅ 서버 시작
app.listen(PORT, () =>
  console.log(`✅ 인증 서버가 포트 ${PORT}에서 실행 중입니다 (중복 로그인 방지 활성화)`)
);