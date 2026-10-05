# DEXO Auth Backend

Node/Express + Passport backend for Google, Discord and Steam.

## Render deployment
1. Upload this folder to a private GitHub repo.
2. Render -> New -> Web Service -> select the repo.
3. Build command: `npm install`
4. Start command: `npm start`
5. Choose Free for testing. Render free web services can sleep after 15 minutes idle.
6. Add environment variables from `.env.example`.
7. Set `BACKEND_URL` to your actual Render service URL, for this project: `https://dexo-auth-backend.onrender.com`.

## OAuth callbacks
After you know your Render URL, register:
Google redirect: https://YOUR-SERVICE.onrender.com/auth/google/callback
Discord redirect: https://YOUR-SERVICE.onrender.com/auth/discord/callback
Steam return URL: https://YOUR-SERVICE.onrender.com/auth/steam/callback

Google JavaScript origin remains the DEXO site if using browser GIS, but this backend uses server-side OAuth so the callback belongs to the backend.

NEVER put GOOGLE_CLIENT_SECRET or DISCORD_CLIENT_SECRET in index.html.
