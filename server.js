require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error("JWT_SECRET must be at least 32 characters.");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: false } : undefined
});

app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(",").map(s => s.trim())
    : true
}));
app.use(express.json({ limit: "20kb" }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 30,
  standardHeaders: "draft-7", legacyHeaders: false,
  message: { error: "Too many attempts. Please wait and try again." }
});
const namePattern = /^[A-Za-z ]+$/;
const phonePattern = /^(07|01)[0-9]{8}$/;

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS members (
      id BIGSERIAL PRIMARY KEY,
      real_name VARCHAR(60) NOT NULL,
      phone VARCHAR(10) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}
function tokenFor(member) {
  return jwt.sign({ sub: String(member.id), phone: member.phone }, JWT_SECRET,
    { expiresIn: "12h", issuer: "member-portal" });
}
function publicMember(row) {
  return { id: row.id, realName: row.real_name, phone: row.phone, createdAt: row.created_at };
}
function requireAuth(req, res, next) {
  const [scheme, token] = (req.get("authorization") || "").split(" ");
  if (scheme !== "Bearer" || !token) return res.status(401).json({ error: "Please log in first." });
  try {
    req.auth = jwt.verify(token, JWT_SECRET, { issuer: "member-portal" });
    next();
  } catch {
    return res.status(401).json({ error: "Session expired. Please log in again." });
  }
}

app.get("/api/health", (_req, res) => res.json({ status: "ok" }));

app.post("/api/signup", authLimiter, async (req, res, next) => {
  try {
    const realName = typeof req.body?.realName === "string" ? req.body.realName.trim() : "";
    const phone = typeof req.body?.phone === "string" ? req.body.phone.trim() : "";
    const password = req.body?.password;

    if (realName.length < 2 || realName.length > 60 || !namePattern.test(realName))
      return res.status(400).json({ error: "Name must contain letters and spaces only (2–60 characters)." });
    if (!phonePattern.test(phone))
      return res.status(400).json({ error: "Phone number must be exactly 10 digits and start with 07 or 01." });
    if (typeof password !== "string" || password.length < 4 || password.length > 10)
      return res.status(400).json({ error: "Password must be 4–10 characters." });

    const duplicatePhone = await pool.query("SELECT id FROM members WHERE phone=$1", [phone]);
    if (duplicatePhone.rowCount)
      return res.status(409).json({ error: "Phone number already registered. Please log in." });

    // Password-only login is required by the original frontend. Reject duplicates to avoid ambiguity.
    // This scan is demo-scale only; real systems should log in using phone + password.
    const hashes = await pool.query("SELECT password_hash FROM members");
    for (const row of hashes.rows) {
      if (await bcrypt.compare(password, row.password_hash))
        return res.status(409).json({ error: "Password already in use. Choose a different one for this password-only demo login." });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO members(real_name,phone,password_hash) VALUES($1,$2,$3) RETURNING id,real_name,phone,created_at",
      [realName, phone, hash]
    );
    const member = result.rows[0];
    res.status(201).json({ message: "Account created.", token: tokenFor(member), member: publicMember(member) });
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "Phone number already registered." });
    next(err);
  }
});

app.post("/api/login", authLimiter, async (req, res, next) => {
  try {
    const password = req.body?.password;
    if (typeof password !== "string" || password.length < 4 || password.length > 10)
      return res.status(400).json({ error: "Enter a password between 4 and 10 characters." });

    const result = await pool.query("SELECT id,real_name,phone,password_hash,created_at FROM members ORDER BY id");
    let match = null;
    for (const row of result.rows) {
      if (await bcrypt.compare(password, row.password_hash)) { match = row; break; }
    }
    if (!match) return res.status(401).json({ error: "Incorrect password." });
    res.json({ message: "Login successful.", token: tokenFor(match), member: publicMember(match) });
  } catch (err) { next(err); }
});

app.get("/api/members", requireAuth, async (_req, res, next) => {
  try {
    const result = await pool.query("SELECT id,real_name,phone,created_at FROM members ORDER BY created_at DESC");
    res.json({ members: result.rows.map(publicMember) });
  } catch (err) { next(err); }
});

app.get("/api/me", requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query("SELECT id,real_name,phone,created_at FROM members WHERE id=$1", [req.auth.sub]);
    if (!result.rowCount) return res.status(404).json({ error: "Member not found." });
    res.json({ member: publicMember(result.rows[0]) });
  } catch (err) { next(err); }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Something went wrong. Please try again later." });
});

initDb().then(() => app.listen(PORT, () => console.log(`Backend listening on ${PORT}`)))
  .catch(err => { console.error("Database initialization failed:", err); process.exit(1); });

process.on("SIGTERM", async () => { await pool.end(); process.exit(0); });
