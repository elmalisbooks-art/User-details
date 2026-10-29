# Member Portal Backend

Node.js 20+, Express, and PostgreSQL backend for the sign-up/login frontend.

## Included
- `POST /api/signup`: validates name, phone and password; saves member.
- `POST /api/login`: logs in using password only, as requested.
- `GET /api/members`: returns registered members after authentication.
- `GET /api/me`: returns the currently authenticated member.
- `GET /api/health`: health check.
- bcrypt password hashing, JWT tokens, Helmet security headers, rate limiting, and parameterized SQL.
- PostgreSQL table is created automatically at startup.

## Run locally
1. Install Node.js 20+ and get a PostgreSQL database.
2. Copy `.env.example` to `.env`.
3. Fill in `DATABASE_URL` and a random `JWT_SECRET` of at least 32 characters.
4. Set `DATABASE_SSL=false` for local PostgreSQL if it does not use SSL.
5. Run:
   ```sh
   npm install
   npm start
   ```
6. Visit `http://localhost:3000/api/health`; expected response: `{"status":"ok"}`.

## API examples

### Sign up
`POST /api/signup`, JSON:
```json
{"realName":"Salim Jimbo","phone":"0792348004","password":"test@123"}
```

### Log in
`POST /api/login`, JSON:
```json
{"password":"test@123"}
```
Successful responses include a JWT token. For protected endpoints send:
`Authorization: Bearer YOUR_TOKEN`

### Get all members
`GET /api/members` returns names, phone numbers and registration dates. Passwords and hashes are never returned.

## Important security note about password-only login
This implements the requested password-only login. It is not recommended for a real public website. The backend rejects passwords already used by another account to prevent ambiguity, but that check scans every account and is suitable only for a small demo. For production, use phone number + password and remove the duplicate-password scan. Also consider whether every member should be allowed to see every other member's phone number.

## Deploy on Render
1. Push this folder to a GitHub repository.
2. In Render, choose **New + → Blueprint** and select the repository containing `render.yaml`.
3. Review the web service and PostgreSQL database, then deploy.
4. Render generates the JWT secret and wires in the database URL.
5. Test `https://YOUR-SERVICE.onrender.com/api/health`.

Hosting plan terms can change; check the current Render dashboard. Never commit `.env` or expose secrets in frontend JavaScript.
