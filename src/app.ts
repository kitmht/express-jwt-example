import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const app = express();
app.use(express.json());

const users = [
  {
    id: 1,
    email: 'user1@example.com',
    password: '$2b$10$qG7J.EsTbUFQatMKAm3gx.wRrrsBaZaoY/WWcebC91d96TCeduSF2',
  },
];

const ACCESS_TOKEN_SECRET_KEY = 'access token secret key';
const REFRESH_TOKEN_SECRET_KEY = 'refresh token secret key';

const generateAccessToken = (email: string) => {
  const payload = { type: 'accessToken', email };
  const options = { expiresIn: '1m' };
  return jwt.sign(payload, ACCESS_TOKEN_SECRET_KEY, options);
};

const generateRefreshToken = (email: string) => {
  const payload = { type: 'refreshToken', email };
  const options = { expiresIn: '2m' };
  return jwt.sign(payload, REFRESH_TOKEN_SECRET_KEY, options);
};

app.post('/account/login', async (req, res) => {
  const { email, password } = req.body;

  const user = users.find((user) => user.email === email);
  if (!user) {
    return res.status(401).json({ message: 'user not registered' });
  }

  if (!(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: 'login failure' });
  }

  const accessToken = generateAccessToken(email);
  const refreshToken = generateRefreshToken(email);
  res.status(200).json({ accessToken, refreshToken });
});

app.post('/account/refresh', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ error: 'リフレッシュトークンがありません' });
  }

  jwt.verify(
    refreshToken,
    REFRESH_TOKEN_SECRET_KEY,
    (err: any, decoded: any) => {
      if (err) {
        return res
          .status(403)
          .json({ error: 'リフレッシュトークンが不正です' });
      }

      const newAccessToken = generateAccessToken(decoded.email);
      res.json({ accessToken: newAccessToken });
    }
  );
});

app.get('/secret', (req, res) => {
  if (!req.headers.authorization) {
    return res.status(401).json({ error: 'アクセストークンがありません' });
  }

  if (req.headers.authorization.split(' ')[0] !== 'Bearer') {
    return res.status(403).json({ error: 'アクセストークンが不正です' });
  }

  const accessToken = req.headers.authorization.split(' ')[1];
  jwt.verify(accessToken, ACCESS_TOKEN_SECRET_KEY, (err, decoded: any) => {
    if (err) {
      return res.status(403).json({ error: 'アクセストークンが不正です' });
    }

    res.json({
      message: 'アクセス成功',
      user: decoded.email,
    });
  });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`server listen http://localhost:${PORT}`));
