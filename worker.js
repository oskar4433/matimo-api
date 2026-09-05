/**
 * Matimo API - Cloudflare Worker
 * D1 veritabanı bağlantı değişkeni: DB
 *
 * Bu dosya şunları içerir:
 *  - ensureSchema(): İlk çalıştırmada tabloları otomatik oluşturur
 *  - GET  /              -> API çalışıyor mu kontrolü
 *  - POST /api/register  -> Yeni öğrenci/üye kaydı
 *  - POST /api/login     -> Giriş, oturum token'ı döner
 *  - GET  /api/me         -> Token ile giriş yapmış kullanıcının bilgileri
 *  - POST /api/logout    -> Oturumu kapatır
 *
 * İzin verilen kaynaklar (CORS):
 *  - https://matimoegitim.com
 *  - https://www.matimoegitim.com
 */

const ALLOWED_ORIGINS = [
  "https://matimoegitim.com",
  "https://www.matimoegitim.com",
];

function corsHeaders(origin) {
  const allowOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonResponse(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(origin),
    },
  });
}

// ---- Veritabanı şemasını oluştur (varsa dokunmaz) ----
async function ensureSchema(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      grade INTEGER,
      membership TEXT NOT NULL DEFAULT 'free',
      created_at TEXT NOT NULL
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT NOT NULL UNIQUE,
      user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `).run();
}

// ---- Şifre işlemleri (Web Crypto - PBKDF2) ----
function bufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function generateSalt() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return bufferToHex(arr.buffer);
}

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map((b) => parseInt(b, 16)));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return bufferToHex(derived);
}

function generateToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return bufferToHex(arr.buffer);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ---- Token'dan kullanıcıyı bul ----
async function getUserFromToken(db, token) {
  if (!token) return null;
  const session = await db
    .prepare("SELECT * FROM sessions WHERE token = ? AND expires_at > ?")
    .bind(token, new Date().toISOString())
    .first();
  if (!session) return null;

  const user = await db
    .prepare("SELECT id, name, email, grade, membership, created_at FROM users WHERE id = ?")
    .bind(session.user_id)
    .first();
  return user;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const url = new URL(request.url);

    // Tarayıcı ön kontrolü (preflight)
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    try {
      await ensureSchema(env.DB);

      // GET / -> Kontrol
      if (url.pathname === "/" && request.method === "GET") {
        return jsonResponse({ status: "ok", message: "Matimo API çalışıyor" }, 200, origin);
      }

      // POST /api/register -> Kayıt
      if (url.pathname === "/api/register" && request.method === "POST") {
        const body = await request.json().catch(() => null);
        if (!body) return jsonResponse({ error: "Geçersiz istek gövdesi" }, 400, origin);

        const { name, email, password, grade } = body;

        if (!name || !email || !password) {
          return jsonResponse({ error: "İsim, e-posta ve şifre zorunludur" }, 400, origin);
        }
        if (!isValidEmail(email)) {
          return jsonResponse({ error: "Geçersiz e-posta adresi" }, 400, origin);
        }
        if (password.length < 6) {
          return jsonResponse({ error: "Şifre en az 6 karakter olmalıdır" }, 400, origin);
        }

        const existing = await env.DB
          .prepare("SELECT id FROM users WHERE email = ?")
          .bind(email.toLowerCase())
          .first();
        if (existing) {
          return jsonResponse({ error: "Bu e-posta adresi zaten kayıtlı" }, 409, origin);
        }

        const salt = generateSalt();
        const passwordHash = await hashPassword(password, salt);
        const createdAt = new Date().toISOString();

        const result = await env.DB
          .prepare(
            "INSERT INTO users (name, email, password_hash, salt, grade, membership, created_at) VALUES (?, ?, ?, ?, ?, 'free', ?)"
          )
          .bind(name, email.toLowerCase(), passwordHash, salt, grade || null, createdAt)
          .run();

        return jsonResponse(
          { status: "ok", message: "Kayıt başarılı", userId: result.meta.last_row_id },
          201,
          origin
        );
      }

      // POST /api/login -> Giriş
      if (url.pathname === "/api/login" && request.method === "POST") {
        const body = await request.json().catch(() => null);
        if (!body) return jsonResponse({ error: "Geçersiz istek gövdesi" }, 400, origin);

        const { email, password } = body;
        if (!email || !password) {
          return jsonResponse({ error: "E-posta ve şifre zorunludur" }, 400, origin);
        }

        const user = await env.DB
          .prepare("SELECT * FROM users WHERE email = ?")
          .bind(email.toLowerCase())
          .first();

        if (!user) {
          return jsonResponse({ error: "E-posta veya şifre hatalı" }, 401, origin);
        }

        const computedHash = await hashPassword(password, user.salt);
        if (computedHash !== user.password_hash) {
          return jsonResponse({ error: "E-posta veya şifre hatalı" }, 401, origin);
        }

        const token = generateToken();
        const createdAt = new Date().toISOString();
        const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 gün

        await env.DB
          .prepare("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
          .bind(token, user.id, createdAt, expiresAt)
          .run();

        return jsonResponse(
          {
            status: "ok",
            token,
            user: {
              id: user.id,
              name: user.name,
              email: user.email,
              grade: user.grade,
              membership: user.membership,
            },
          },
          200,
          origin
        );
      }

      // GET /api/me -> Giriş yapmış kullanıcı bilgisi
      if (url.pathname === "/api/me" && request.method === "GET") {
        const authHeader = request.headers.get("Authorization") || "";
        const token = authHeader.replace("Bearer ", "").trim();
        const user = await getUserFromToken(env.DB, token);

        if (!user) {
          return jsonResponse({ error: "Giriş yapılmamış veya oturum süresi dolmuş" }, 401, origin);
        }
        return jsonResponse({ status: "ok", user }, 200, origin);
      }

      // POST /api/logout -> Oturumu kapat
      if (url.pathname === "/api/logout" && request.method === "POST") {
        const authHeader = request.headers.get("Authorization") || "";
        const token = authHeader.replace("Bearer ", "").trim();
        if (token) {
          await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
        }
        return jsonResponse({ status: "ok", message: "Çıkış yapıldı" }, 200, origin);
      }

      // Eşleşen rota yok
      return jsonResponse({ error: "Bulunamadı" }, 404, origin);
    } catch (err) {
      return jsonResponse({ error: "Sunucu hatası", detail: String(err) }, 500, origin);
    }
  },
};
