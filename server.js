const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const cors = require('cors');
const mysql = require('mysql2/promise');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const DiscordStrategy = require('passport-discord').Strategy;
const SteamStrategy = require('passport-steam').Strategy;

const app = express();
const PORT = process.env.PORT || 10000;
const FRONTEND = process.env.FRONTEND_URL || 'https://dexer.site.je';
const BACKEND = (process.env.BACKEND_URL || 'https://dexo-auth-backend.onrender.com').replace(/\/$/, '');

const dbOptions = {
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  connectionLimit: 5,
  waitForConnections: true,
  queueLimit: 0,
  charset: 'utf8mb4'
};

const db = mysql.createPool(dbOptions);

const sessionStore = new MySQLStore({
  host: dbOptions.host,
  port: dbOptions.port,
  user: dbOptions.user,
  password: dbOptions.password,
  database: dbOptions.database,
  createDatabaseTable: false,
  schema: {
    tableName: 'user_sessions',
    columnNames: {
      session_id: 'id',
      expires: 'expires_at',
      data: 'session_data'
    }
  }
});

app.set('trust proxy', 1);
app.use(cors({ origin: FRONTEND, credentials: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'CHANGE_THIS_SECRET',
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
}));
app.use(passport.initialize());
app.use(passport.session());

function profileData(provider, profile) {
  if (provider === 'google') {
    return {
      provider: 'google',
      id: profile.id,
      name: profile.displayName || profile.name?.givenName || 'Google User',
      email: profile.emails?.[0]?.value || null,
      avatar: profile.photos?.[0]?.value || null
    };
  }
  if (provider === 'discord') {
    return {
      provider: 'discord',
      id: profile.id,
      name: profile.global_name || profile.username || 'Discord User',
      email: profile.email || null,
      avatar: profile.avatar ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png` : null
    };
  }
  return {
    provider: 'steam',
    id: profile._json?.steamid || profile.id,
    name: profile.displayName || profile._json?.personaname || 'Steam User',
    email: null,
    avatar: profile.photos?.[2]?.value || profile.photos?.[0]?.value || null
  };
}

passport.serializeUser((user, done) => done(null, user.userId));
passport.deserializeUser(async (userId, done) => {
  try {
    const [rows] = await db.execute(
      `SELECT id, username, display_name, email, avatar_url, created_at, updated_at, last_login_at, status
       FROM users WHERE id = ? LIMIT 1`,
      [userId]
    );
    if (!rows.length || rows[0].status !== 'active') return done(null, false);
    done(null, { userId: rows[0].id, ...rows[0] });
  } catch (err) {
    done(err);
  }
});

async function findOrCreateAccount(data, req) {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    const [existing] = await conn.execute(
      `SELECT oa.user_id, oa.id AS oauth_id
       FROM oauth_accounts oa
       WHERE oa.provider = ? AND oa.provider_user_id = ? LIMIT 1`,
      [data.provider, data.id]
    );

    let userId;

    if (existing.length) {
      if (req.oauthMode === 'link' && existing[0].user_id !== req.user?.userId) {
        throw new Error(`ACCOUNT_ALREADY_LINKED:${data.provider}`);
      }
      userId = existing[0].user_id;
      await conn.execute(
        `UPDATE oauth_accounts
         SET provider_username=?, provider_email=?, provider_avatar_url=?, last_login_at=NOW()
         WHERE id=?`,
        [data.name, data.email, data.avatar, existing[0].oauth_id]
      );
      await conn.execute(
        `UPDATE users SET display_name=?, email=COALESCE(?, email), avatar_url=COALESCE(?, avatar_url), last_login_at=NOW()
         WHERE id=?`,
        [data.name, data.email, data.avatar, userId]
      );
    } else if (req.user) {
      // Linking a new provider to the account that is already logged in.
      userId = req.user.userId;
      const [owner] = await conn.execute(
        `SELECT id FROM oauth_accounts WHERE provider=? AND provider_user_id=? LIMIT 1`,
        [data.provider, data.id]
      );
      if (owner.length && owner[0].user_id !== userId) {
        throw new Error(`ACCOUNT_ALREADY_LINKED:${data.provider}`);
      }
      await conn.execute(
        `INSERT INTO oauth_accounts
         (user_id, provider, provider_user_id, provider_username, provider_email, provider_avatar_url, last_login_at)
         VALUES (?, ?, ?, ?, ?, ?, NOW())`,
        [userId, data.provider, data.id, data.name, data.email, data.avatar]
      );
      await conn.execute(
        `UPDATE users SET display_name=COALESCE(display_name, ?), email=COALESCE(email, ?), avatar_url=COALESCE(avatar_url, ?), updated_at=NOW()
         WHERE id=?`,
        [data.name, data.email, data.avatar, userId]
      );
    } else {
      // Try email match for Google/Discord, otherwise create a new DEXO account.
      if (data.email) {
        const [byEmail] = await conn.execute(`SELECT id FROM users WHERE email=? LIMIT 1`, [data.email]);
        if (byEmail.length) userId = byEmail[0].id;
      }
      if (!userId) {
        const [insertUser] = await conn.execute(
          `INSERT INTO users (username, display_name, email, avatar_url, last_login_at)
           VALUES (?, ?, ?, ?, NOW())`,
          [data.name, data.name, data.email, data.avatar]
        );
        userId = insertUser.insertId;
      } else {
        await conn.execute(
          `UPDATE users SET display_name=?, avatar_url=COALESCE(?, avatar_url), last_login_at=NOW() WHERE id=?`,
          [data.name, data.avatar, userId]
        );
      }
      await conn.execute(
        `INSERT INTO oauth_accounts
         (user_id, provider, provider_user_id, provider_username, provider_email, provider_avatar_url, last_login_at)
         VALUES (?, ?, ?, ?, ?, ?, NOW())`,
        [userId, data.provider, data.id, data.name, data.email, data.avatar]
      );
    }

    await conn.execute(
      `INSERT INTO login_logs (user_id, provider, provider_user_id, ip_address, user_agent, success)
       VALUES (?, ?, ?, ?, ?, 1)`,
      [userId, data.provider, data.id, req.ip || null, req.get('user-agent') || null]
    );

    await conn.commit();
    return userId;
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

async function authDone(req, res, data, mode) {
  try {
    req.oauthMode = mode;
    const userId = await findOrCreateAccount(data, req);
    req.login({ userId }, err => {
      if (err) return res.redirect(`${FRONTEND}/?auth=${data.provider}_failed`);
      const action = mode === 'link' ? 'linked' : 'success';
      return res.redirect(`${FRONTEND}/?auth=${action}&provider=${data.provider}`);
    });
  } catch (err) {
    console.error('OAuth database error:', err.message);
    const reason = err.message.startsWith('ACCOUNT_ALREADY_LINKED') ? 'already_linked' : 'database_error';
    return res.redirect(`${FRONTEND}/?auth=${data.provider}_failed&reason=${reason}`);
  }
}

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: BACKEND + '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => done(null, profileData('google', profile))));

passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: BACKEND + '/auth/discord/callback',
  scope: ['identify', 'email']
}, async (accessToken, refreshToken, profile, done) => done(null, profileData('discord', profile))));

passport.use(new SteamStrategy({
  returnURL: BACKEND + '/auth/steam/callback',
  realm: BACKEND + '/',
  apiKey: process.env.STEAM_API_KEY || ''
}, async (identifier, profile, done) => done(null, profileData('steam', profile))));

app.get('/', (req, res) => res.json({ ok: true, service: 'DEXO Auth Backend' }));
app.get('/health', async (req, res) => {
  try {
    await db.query('SELECT 1');
    res.json({ ok: true, database: 'connected' });
  } catch (err) {
    console.error('DB health error:', err.message);
    res.status(503).json({ ok: false, database: 'error' });
  }
});

app.get('/me', (req, res) => res.json({ authenticated: !!req.user, user: req.user || null }));

app.get('/account', async (req, res) => {
  if (!req.user) return res.status(401).json({ ok: false, authenticated: false });
  const [rows] = await db.execute(
    `SELECT oa.provider, oa.provider_user_id, oa.provider_username, oa.provider_email, oa.provider_avatar_url, oa.created_at, oa.last_login_at
     FROM oauth_accounts oa WHERE oa.user_id=? ORDER BY oa.created_at`,
    [req.user.userId]
  );
  res.json({ ok: true, user: req.user, linked_accounts: rows });
});

app.get('/unlink/:provider', async (req, res) => {
  if (!req.user) return res.status(401).json({ ok: false, error: 'not_authenticated' });
  const provider = req.params.provider;
  if (!['google', 'discord', 'steam'].includes(provider)) return res.status(400).json({ ok: false, error: 'invalid_provider' });
  const [count] = await db.execute(`SELECT COUNT(*) AS total FROM oauth_accounts WHERE user_id=?`, [req.user.userId]);
  if (Number(count[0].total) <= 1) return res.status(400).json({ ok: false, error: 'cannot_unlink_last_login' });
  await db.execute(`DELETE FROM oauth_accounts WHERE user_id=? AND provider=?`, [req.user.userId, provider]);
  res.redirect(FRONTEND + '/?auth=unlinked&provider=' + provider);
});

app.get('/logout', (req, res) => {
  req.logout(() => req.session.destroy(() => res.redirect(FRONTEND)));
});

function startAuth(provider, req, res, next) {
  if (req.query.mode === 'link' && !req.user) return res.redirect(FRONTEND + '/?auth=link_failed&reason=login_required');
  req.session.oauthMode = req.query.mode === 'link' ? 'link' : 'login';
  next();
}

app.get('/auth/google', startAuth.bind(null, 'google'), passport.authenticate('google', { scope: ['profile', 'email'], session: false }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: FRONTEND + '/?auth=google_failed', session: false }), async (req, res) => {
  const mode = req.session.oauthMode || 'login';
  delete req.session.oauthMode;
  await authDone(req, res, req.user, mode);
});

app.get('/auth/discord', startAuth.bind(null, 'discord'), passport.authenticate('discord', { session: false }));
app.get('/auth/discord/callback', passport.authenticate('discord', { failureRedirect: FRONTEND + '/?auth=discord_failed', session: false }), async (req, res) => {
  const mode = req.session.oauthMode || 'login';
  delete req.session.oauthMode;
  await authDone(req, res, req.user, mode);
});

app.get('/auth/steam', startAuth.bind(null, 'steam'), passport.authenticate('steam', { session: false }));
app.get('/auth/steam/callback', passport.authenticate('steam', { failureRedirect: FRONTEND + '/?auth=steam_failed', session: false }), async (req, res) => {
  const mode = req.session.oauthMode || 'login';
  delete req.session.oauthMode;
  await authDone(req, res, req.user, mode);
});

app.listen(PORT, '0.0.0.0', () => console.log(`DEXO auth listening on ${PORT}`));
