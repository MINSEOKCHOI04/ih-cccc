const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const SESSION_TTL_MS = 120 * 60 * 1000; // 2시간 유지
// email -> { sessionId, ip, last }
const activeSessions = new Map();

const nowKR = () => new Date().toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' });
const clientIP = (req) => {
  const xff = req.headers['x-forwarded-for'] || '';
  return (xff.split(',')[0] || '').trim() || req.connection.remoteAddress || '';
};

// 만료된 세션 자동 제거
function pruneExpired(email) {
  const s = activeSessions.get(email);
  if (!s) return;
  if (Date.now() - s.last > SESSION_TTL_MS) activeSessions.delete(email);
}

app.get('/', (_, res) => res.send('🚀 인증 서버 실행 중입니다.'));

// ✅ 로그인 (중복 로그인 시 기존 세션 강제 종료)
app.all('/auth', (req, res) => {
  const usersPath = path.join(__dirname, 'users.json');
  const users = JSON.parse(fs.readFileSync(usersPath, 'utf-8'));

  const q = req.method === 'GET' ? req.query : req.body;
  const email = String(q.email || '').trim();
  const code = String(q.code || '').trim();
  const ip = clientIP(req);
  const time = nowKR();

  if (!email || !code) return res.json({ ok: false, msg: 'email, code 필요' });
  if (!users[email] || users[email] !== code) {
    console.log(`[실패] 🔴 ${time} | ${email} | IP:${ip}`);
    return res.json({ ok: false, msg: '아이디 또는 비밀번호가 올바르지 않습니다.' });
  }

  pruneExpired(email);
  const cur = activeSessions.get(email);

  // 🔥 기존 로그인 세션이 존재하면 즉시 강제 로그아웃
  if (cur) {
    console.log(`[중복로그인] ⚠️ ${time} | ${email} | 기존 세션 강제 종료`);
    activeSessions.delete(email);
  }

  // 새 로그인 세션 생성
  const sessionId = 'sess_' + crypto.randomBytes(8).toString('hex');
  activeSessions.set(email, { sessionId, ip, last: Date.now() });

  console.log(`[로그인] 🟢 ${time} | ${email} | IP:${ip}`);
  return res.json({ ok: true, sessionId, ttlMs: SESSION_TTL_MS });
});

// ✅ 세션 확인
app.get('/check', (req, res) => {
  const email = String(req.query.email || '').trim();
  const sessionId = String(req.query.sessionId || '').trim();
  if (!email || !sessionId) return res.json({ ok: false, msg: 'email, sessionId 필요' });

  pruneExpired(email);
  const cur = activeSessions.get(email);
  if (!cur) return res.json({ ok: false, expired: true });

  const valid = Date.now() - cur.last <= SESSION_TTL_MS;
  if (!valid) {
    activeSessions.delete(email);
    return res.json({ ok: false, expired: true });
  }

  const same = cur.sessionId === sessionId;
  return res.json({
    ok: valid && same,
    sameSession: same,
    expiresInMs: SESSION_TTL_MS - (Date.now() - cur.last)
  });
});

// ✅ 하트비트 (세션 유지)
app.post('/touch', (req, res) => {
  const { email, sessionId } = req.body || {};
  if (!email || !sessionId) return res.json({ ok: false, msg: 'email, sessionId 필요' });
  const cur = activeSessions.get(email);
  if (!cur) return res.json({ ok: false, expired: true });
  if (cur.sessionId !== sessionId) return res.json({ ok: false, msg: '다른 로그인으로 대체됨' });
  cur.last = Date.now();
  return res.json({ ok: true });
});

// ✅ 로그아웃
app.all('/logout', (req, res) => {
  const q = req.method === 'GET' ? req.query : req.body;
  const email = String(q.email || '').trim();
  const sessionId = String(q.sessionId || '').trim();

  const cur = activeSessions.get(email);
  if (cur && cur.sessionId === sessionId) {
    activeSessions.delete(email);
    console.log(`[로그아웃] 🔓 ${nowKR()} | ${email}`);
    return res.json({ ok: true, msg: '로그아웃 완료' });
  }
  return res.json({ ok: false, msg: '로그인 상태가 아니거나 다른 세션' });
});

app.listen(PORT, () =>
  console.log(`✅ 서버가 포트 ${PORT}에서 실행 중입니다`)
);