const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const cors = require('cors');

dotenv.config();

const app = express();
const port = 5000;

app.use(cors());
app.use(express.json());

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// 회원가입 엔드포인트
app.post('/api/signup', async (req, res) => {
  const { username, password, name, birth, pnum, email } = req.body;

  try {
    const saltRounds = 10;
    const password_hash = await bcrypt.hash(password, saltRounds);

    const query = `
      INSERT INTO users (username, password_hash, name, birth, pnum, email, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, NOW())
      RETURNING id;
    `;
    const values = [username, password_hash, name, birth, pnum, email];
    const result = await pool.query(query, values);

    const userId = result.rows[0].id;

    await pool.query(
      'INSERT INTO password_history (user_id, password_hash, changed_at) VALUES ($1, $2, NOW())',
      [userId, password_hash]
    );

    res.status(201).json({ message: '회원가입 성공', userId: userId });
  } catch (err) {
    console.error('회원가입 오류:', err);
    res.status(500).json({ error: '회원가입 실패' });
  }
});

// 로그인 엔드포인트
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = userResult.rows[0];

    if (!user) {
      return res.status(400).json({ error: '잘못된 아이디 또는 비밀번호입니다.' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ error: '잘못된 아이디 또는 비밀번호입니다.' });
    }

    const userInfo = {
      username: user.username,
      name: user.name,
      birth: user.birth,
      pnum: user.pnum,
      email: user.email,
      created_at: user.created_at,
    };

    res.json({ message: '로그인 성공', user: userInfo });
  } catch (err) {
    console.error('로그인 오류:', err);
    res.status(500).json({ error: '로그인 실패' });
  }
});

// 비밀번호 변경 엔드포인트
app.post('/api/changepassword', async (req, res) => {
  const { username, currentPassword, newPassword } = req.body;

  console.log("Received data:", { username, currentPassword, newPassword });

  try {
    const userResult = await pool.query('SELECT id, password_hash FROM users WHERE username = $1', [username]);
    const user = userResult.rows[0];

    if (!user) {
      console.error("사용자를 찾을 수 없습니다.");
      return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    }

    console.log("Found user:", user);

    const userId = user.id;

    const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isMatch) {
      console.error("현재 비밀번호가 일치하지 않습니다.");
      return res.status(400).json({ error: '현재 비밀번호가 일치하지 않습니다.' });
    }

    console.log("Checking password history for user ID:", userId);
    const historyResult = await pool.query(
      'SELECT password_hash FROM password_history WHERE user_id = $1 ORDER BY changed_at DESC LIMIT 3',
      [userId]
    );

    let isRecentPassword = false;

    for (const row of historyResult.rows) {
      const match = await bcrypt.compare(newPassword, row.password_hash);
      console.log(`Comparing new password with history password: ${row.password_hash}, match: ${match}`);
      if (match) {
        isRecentPassword = true;
        break;
      }
    }

    if (isRecentPassword) {
      console.error("최근 3회 사용한 비밀번호로는 변경할 수 없습니다.");
      return res.status(400).json({ error: '최근 3회 사용한 비밀번호로는 변경할 수 없습니다.' });
    }

    const saltRounds = 10;
    const newHashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // users 테이블의 비밀번호 업데이트
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHashedPassword, userId]);

    // password_history 테이블에 새로운 비밀번호 추가
    await pool.query(
      'INSERT INTO password_history (user_id, password_hash, changed_at) VALUES ($1, $2, NOW())',
      [userId, newHashedPassword]
    );

    // 최근 3개를 초과하는 이전 비밀번호 이력 삭제
    const deleteResult = await pool.query(
      `DELETE FROM password_history 
       WHERE user_id = $1 
       AND id NOT IN (
         SELECT id FROM password_history 
         WHERE user_id = $1 
         ORDER BY changed_at DESC 
         LIMIT 3
       )`,
      [userId]
    );

    // 삭제 결과 확인
    console.log(`삭제된 행 개수: ${deleteResult.rowCount}`);

    res.status(200).json({ message: '비밀번호가 성공적으로 변경되었습니다.' });
  } catch (err) {
    console.error('비밀번호 변경 오류:', err);
    res.status(500).json({ error: '비밀번호 변경에 실패했습니다.' });
  }
});


app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});