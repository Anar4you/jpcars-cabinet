
const express = require("express");
const session = require("express-session");
const { DatabaseSync } = require("node:sqlite");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const archiver = require("archiver");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");

const app = express();
const ROOT = __dirname;
const PORT = process.env.PORT || 3000;
const DATA_ROOT = process.env.DATA_DIR || ROOT;
const DB_PATH = process.env.DB_PATH || path.join(DATA_ROOT, "data", "jpcars.db");
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(DATA_ROOT, "uploads");

const IS_PROD = process.env.NODE_ENV === "production";
const SESSION_SECRET = process.env.SESSION_SECRET || (IS_PROD ? "" : "CHANGE-ME-JPCARS-LOCAL");
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || (IS_PROD ? "" : "change-me");

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const TELEGRAM_BOT_USERNAME = (process.env.TELEGRAM_BOT_USERNAME || "").replace(/^@/,"");
const TELEGRAM_WEBHOOK_SECRET = process.env.TELEGRAM_WEBHOOK_SECRET || "";
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "").replace(/\/+$/,"");


if (IS_PROD && (!SESSION_SECRET || SESSION_SECRET.length < 32)) {
  console.error("FATAL: SESSION_SECRET must be set and at least 32 characters in production.");
  process.exit(1);
}
if (IS_PROD && (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12)) {
  console.error("FATAL: ADMIN_PASSWORD must be set and at least 12 characters in production.");
  process.exit(1);
}


fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new DatabaseSync(DB_PATH);
db.exec("PRAGMA journal_mode = WAL;");

db.exec(`
CREATE TABLE IF NOT EXISTS app_sessions (
  sid TEXT PRIMARY KEY,
  sess TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_app_sessions_expires ON app_sessions(expires_at);

CREATE TABLE IF NOT EXISTS access_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  deal_id INTEGER,
  resource_type TEXT NOT NULL,
  resource_id INTEGER,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  ip TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_access_logs_deal ON access_logs(deal_id, id DESC);
CREATE TABLE IF NOT EXISTS staff_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  login TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'manager',
  active INTEGER NOT NULL DEFAULT 1,
  telegram_chat_id TEXT,
  telegram_username TEXT,
  telegram_first_name TEXT,
  telegram_connected_at TEXT,
  notify_client_uploads INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

`);

class SQLiteSessionStore extends session.Store {
  get(sid, cb) {
    try {
      const now=Date.now();
      db.prepare("DELETE FROM app_sessions WHERE expires_at < ?").run(now);
      const row=db.prepare("SELECT sess,expires_at FROM app_sessions WHERE sid=?").get(sid);
      if(!row || row.expires_at < now) return cb(null,null);
      cb(null,JSON.parse(row.sess));
    } catch(e) { cb(e); }
  }
  set(sid, sess, cb) {
    try {
      const maxAge=sess?.cookie?.maxAge || 1000*60*60*12;
      const expiresAt=Date.now()+maxAge;
      db.prepare(`INSERT INTO app_sessions(sid,sess,expires_at) VALUES(?,?,?)
        ON CONFLICT(sid) DO UPDATE SET sess=excluded.sess,expires_at=excluded.expires_at`)
        .run(sid,JSON.stringify(sess),expiresAt);
      cb && cb(null);
    } catch(e) { cb && cb(e); }
  }
  destroy(sid, cb) {
    try { db.prepare("DELETE FROM app_sessions WHERE sid=?").run(sid); cb && cb(null); }
    catch(e) { cb && cb(e); }
  }
  touch(sid, sess, cb) { this.set(sid,sess,cb); }
}
const sessionStore=new SQLiteSessionStore();
function hashPassword(password,salt=crypto.randomBytes(16).toString("hex")){
  const hash=crypto.scryptSync(password,salt,64).toString("hex");
  return {salt,hash};
}
function verifyPassword(password,salt,expected){
  try{
    const actual=crypto.scryptSync(password,salt,64);
    const exp=Buffer.from(expected,"hex");
    return actual.length===exp.length && crypto.timingSafeEqual(actual,exp);
  }catch(e){ return false; }
}
function ensureInitialAdmin(){
  const row=db.prepare("SELECT COUNT(*) c FROM staff_users").get();
  if(Number(row.c)>0) return;
  const initial=ADMIN_PASSWORD || "change-me";
  const p=hashPassword(initial);
  db.prepare("INSERT INTO staff_users(name,login,password_hash,password_salt,role,active) VALUES(?,?,?,?,?,1)")
    .run("Администратор JPCars","admin",p.hash,p.salt,"admin");
}
ensureInitialAdmin();

function currentStaff(req){
  if(!req.session?.staffId) return null;
  return db.prepare("SELECT id,name,login,role,active FROM staff_users WHERE id=? AND active=1")
    .get(req.session.staffId) || null;
}
function actorName(req){
  const u=currentStaff(req);
  return u ? `${u.name} (${u.login})` : "anonymous";
}


function audit(req,{dealId=null,type="system",resourceId=null,actor=null,action="view"}={}) {
  try {
    const ip=(req.ip || req.headers["x-forwarded-for"] || "").toString().slice(0,120);
    db.prepare("INSERT INTO access_logs(deal_id,resource_type,resource_id,actor,action,ip) VALUES(?,?,?,?,?,?)")
      .run(dealId,type,resourceId,actor || actorName(req),action,ip);
  } catch(e) { console.error("audit error",e); }
}


const FLOWS = {
  Japan: [
    "Консультация",
    "Заключение договора",
    "Оплата комиссии",
    "Торги на аукционе",
    "Автомобиль выиграли на аукционе",
    "Сформированы платежные документы",
    "Автомобиль оплачен",
    "Автомобиль пришел на стоянку в Японии (Тояма)",
    "Получены фото, видео и опись со стоянки",
    "Назначен корабль и порт выхода",
    "Автомобиль отправлен в порт отправки",
    "Автомобиль погружен на корабль и вышел во Владивосток",
    "Автомобиль пришел во Владивосток на СВХ",
    "Выставлена таможенная пошлина для оплаты",
    "Таможенная пошлина оплачена",
    "Автомобиль выпущен с СВХ",
    "Автомобиль забрали",
    "Автомобиль прошел лабораторию",
    "Автомобиль доставлен в транспортную компанию",
    "Документы ЭПТС и СБКТС получены",
    "Автомобиль отправлен из Владивостока до города клиента",
    "Автомобиль в пути",
    "Автомобиль получен",
    "Автомобиль готов"
  ],
  Korea: [
    "Консультация",
    "Заключение договора",
    "Оплата комиссии",
    "Поиск автомобиля",
    "Автомобиль нашли и забронировали",
    "Сформированы платежные документы",
    "Автомобиль оплачен",
    "Автомобиль пришел на стоянку в Инчхоне",
    "Получены фото, видео и опись со стоянки",
    "Назначен корабль и порт выхода",
    "Автомобиль отправлен в порт отправки",
    "Автомобиль погружен на корабль и вышел во Владивосток",
    "Автомобиль пришел во Владивосток на СВХ",
    "Выставлена таможенная пошлина для оплаты",
    "Таможенная пошлина оплачена",
    "Автомобиль выпущен с СВХ",
    "Автомобиль забрали",
    "Автомобиль прошел лабораторию",
    "Автомобиль доставлен в транспортную компанию",
    "Документы ЭПТС и СБКТС получены",
    "Автомобиль отправлен из Владивостока до города клиента",
    "Автомобиль в пути",
    "Автомобиль получен",
    "Автомобиль готов"
  ],
  China: [
    "Консультация",
    "Заключение договора",
    "Оплата комиссии",
    "Поиск автомобиля",
    "Автомобиль нашли и забронировали",
    "Сформированы платежные документы",
    "Автомобиль оплачен",
    "Автомобиль забрали от дилера",
    "Автомобиль отправили в Суйфэньхэ",
    "Автомобиль пришел в Суйфэньхэ",
    "Автомобиль готовится к экспорту",
    "Автомобиль погружен на автовоз",
    "Автомобиль выехал в Уссурийск",
    "Автомобиль пришел в Уссурийск",
    "Выставлена таможенная пошлина для оплаты",
    "Таможенная пошлина оплачена",
    "Автомобиль выпущен с СВХ",
    "Автомобиль забрали",
    "Автомобиль прошел лабораторию",
    "Автомобиль пришел на стоянку JPCars в Уссурийске",
    "Автомобиль доставлен в транспортную компанию во Владивосток",
    "Документы ЭПТС и СБКТС получены",
    "Автомобиль отправлен из Владивостока до города клиента",
    "Автомобиль в пути",
    "Автомобиль получен",
    "Автомобиль готов"
  ]
};

const COUNTRY_NAMES = { Japan: "Япония", Korea: "Южная Корея", China: "Китай" };

const DOC_RULES = {
  Japan: [
    "Нотариальная выписка паспорта",
    "ИНН",
    "СНИЛС",
    "Подтверждение оплаты / документы платежного агента",
    "Инвойс"
  ],
  Korea: [
    "Нотариальная выписка паспорта",
    "ИНН",
    "СНИЛС",
    "Подтверждение оплаты / документы платежного агента",
    "Инвойс"
  ],
  China: [
    "Нотариальная выписка паспорта",
    "ИНН",
    "СНИЛС",
    "Чек ВТБ Банка",
    "Инвойс",
    "Подписанный контракт"
  ]
};

db.exec(`
CREATE TABLE IF NOT EXISTS deals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT UNIQUE NOT NULL,
  client_name TEXT NOT NULL,
  client_phone TEXT,
  country TEXT NOT NULL,
  stage INTEGER NOT NULL DEFAULT 0,
  make TEXT,
  model TEXT,
  year INTEGER,
  vin TEXT,
  mileage INTEGER,
  purchase_date TEXT,
  expected_price INTEGER DEFAULT 0,
  current_location TEXT,
  departure_place TEXT,
  tracking_url TEXT,
  departure_date TEXT,
  eta TEXT,
  arrival_place TEXT,
  car_price INTEGER DEFAULT 0,
  country_costs INTEGER DEFAULT 0,
  delivery INTEGER DEFAULT 0,
  customs_duty INTEGER DEFAULT 0,
  customs_clearance INTEGER DEFAULT 0,
  commission INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS documents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  deal_id INTEGER NOT NULL,
  category TEXT NOT NULL,
  original_name TEXT NOT NULL,
  stored_name TEXT NOT NULL,
  uploader TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS media (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  deal_id INTEGER NOT NULL,
  kind TEXT NOT NULL,
  caption TEXT,
  original_name TEXT NOT NULL,
  stored_name TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  deal_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  note TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);


try { db.exec("ALTER TABLE deals ADD COLUMN manager_note TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE deals ADD COLUMN transport_company TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE deals ADD COLUMN waybill TEXT"); } catch(e) {}

try { db.exec("ALTER TABLE deals ADD COLUMN access_enabled INTEGER DEFAULT 1"); } catch(e) {}
try { db.exec("ALTER TABLE documents ADD COLUMN status TEXT DEFAULT 'uploaded'"); } catch(e) {}
try { db.exec("ALTER TABLE documents ADD COLUMN manager_comment TEXT"); } catch(e) {}

try { db.exec("ALTER TABLE deals ADD COLUMN archived INTEGER DEFAULT 0"); } catch(e) {}

try { db.exec("ALTER TABLE deals ADD COLUMN telegram_chat_id TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE deals ADD COLUMN telegram_username TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE deals ADD COLUMN telegram_first_name TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE deals ADD COLUMN telegram_connected_at TEXT"); } catch(e) {}

try { db.exec("ALTER TABLE staff_users ADD COLUMN telegram_chat_id TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE staff_users ADD COLUMN telegram_username TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE staff_users ADD COLUMN telegram_first_name TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE staff_users ADD COLUMN telegram_connected_at TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE staff_users ADD COLUMN notify_client_uploads INTEGER NOT NULL DEFAULT 1"); } catch(e) {}
try { db.exec("ALTER TABLE deals ADD COLUMN telegram_notifications_enabled INTEGER NOT NULL DEFAULT 1"); } catch(e) {}


db.exec(`
CREATE TABLE IF NOT EXISTS notification_logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  deal_id INTEGER NOT NULL,
  channel TEXT NOT NULL,
  event TEXT NOT NULL,
  recipient TEXT,
  success INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_notification_logs_deal ON notification_logs(deal_id,id DESC);
`);

db.exec(`
CREATE TABLE IF NOT EXISTS payments(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  deal_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  amount INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'expected',
  note TEXT,
  document_name TEXT,
  document_stored TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);



if (!db.prepare("SELECT id FROM deals LIMIT 1").get()) {
  const token = crypto.randomBytes(24).toString("base64url");
  const r = db.prepare(`
    INSERT INTO deals (
      token, client_name, client_phone, country, stage,
      make, model, year, vin, mileage, purchase_date,
      expected_price, current_location, departure_place, tracking_url,
      departure_date, eta, arrival_place,
      car_price, country_costs, delivery, customs_duty, customs_clearance, commission
    )
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    token, "Иван Иванов", "+7 900 000-00-00", "Japan", 11,
    "Toyota", "Crown Sport", 2025, "AZSH35-0001234", 8500, "2026-08-14",
    3685000, "Японское море", "Тояма", "https://www.marinetraffic.com/",
    "2026-08-15", "2026-08-20", "Владивосток",
    2450000, 180000, 150000, 720000, 35000, 150000
  );
  db.prepare("INSERT INTO events(deal_id,title,note) VALUES(?,?,?)")
    .run(Number(r.lastInsertRowid), FLOWS.Japan[11], "Автомобиль вышел во Владивосток.");
}

app.use("/assets", express.static(path.join(ROOT, "assets")));

if (IS_PROD) app.set("trust proxy", 1);

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: "same-origin" }
}));

const loginLimiter=rateLimit({
  windowMs: 15*60*1000,
  limit: 8,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: "Слишком много попыток входа. Попробуйте позже."
});

const publicLimiter=rateLimit({
  windowMs: 15*60*1000,
  limit: 300,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: "Слишком много запросов. Попробуйте позже."
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  store: sessionStore,
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: IS_PROD,
    maxAge: 1000 * 60 * 60 * 12
  }
}));

app.use((req,res,next)=>{
  // Telegram is not a browser and therefore does not send Origin/Referer.
  // This endpoint is protected separately by TELEGRAM_WEBHOOK_SECRET.
  if(req.path==="/telegram/webhook") return next();
  if(!IS_PROD || !["POST","PUT","PATCH","DELETE"].includes(req.method)) return next();
  const expected=`${req.protocol}://${req.get("host")}`;
  const origin=req.get("origin");
  const referer=req.get("referer");
  const sameOrigin=(origin && origin===expected) || (!origin && referer && referer.startsWith(expected+"/"));
  if(!sameOrigin) {
    audit(req,{type:"security",actor:req.session?.admin?"admin":"public",action:"csrf_block"});
    return res.status(403).send("Запрос отклонён системой безопасности.");
  }
  next();
});


const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => cb(null, crypto.randomUUID() + path.extname(decodeUploadName(file.originalname)))
});
const ALLOWED_MIME = new Set([
  "application/pdf",
  "image/jpeg","image/png","image/webp",
  "video/mp4","video/quicktime",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/zip"
]);
const ALLOWED_EXT = new Set([".pdf",".jpg",".jpeg",".png",".webp",".mp4",".mov",".doc",".docx",".zip"]);

const upload = multer({
  storage,
  limits: { fileSize: 30 * 1024 * 1024, files: 20 },
  fileFilter: (_req,file,cb) => {
    const ext=path.extname(decodeUploadName(file.originalname)).toLowerCase();
    if (!ALLOWED_MIME.has(file.mimetype) || !ALLOWED_EXT.has(ext)) return cb(new Error("Недопустимый тип файла"));
    cb(null,true);
  }
});

const esc = s => String(s ?? "").replace(/[&<>"']/g, m => ({
  "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
}[m]));
const money = n => Number(n || 0).toLocaleString("ru-RU") + " ₽";

const decodeUploadName = name => {
  if (!name) return "";
  try {
    const fixed = Buffer.from(name, "latin1").toString("utf8");
    // Use repaired string only when it looks like valid UTF-8 and differs meaningfully.
    if (fixed && !fixed.includes("�")) return fixed;
  } catch(e) {}
  return name;
};


function shell(title, body, isAdmin=false) {
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <meta name="theme-color" content="#15263d">
  <title>${esc(title)} — JPCars</title>
  <style>
  :root{
    --brand:#15263d;--brand2:#1c2a3f;--red:#e9494c;--red-soft:#fff0f0;
    --bg:#f4f6f8;--card:#fff;--text:#17202c;--muted:#737c88;--line:#e7eaee;
    --green:#18855b;--green-soft:#eaf7f1;--shadow:0 8px 30px rgba(21,38,61,.06)
  }
  *{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif;-webkit-font-smoothing:antialiased}
  a{color:inherit}.top{height:76px;background:rgba(255,255,255,.96);border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 28px;position:sticky;top:0;z-index:30;backdrop-filter:blur(12px)}
  .brand-logo{width:164px;height:58px;object-fit:contain;object-position:left center}.top-right{font-size:13px;color:var(--muted);display:flex;align-items:center;gap:16px}.top-right a{text-decoration:none;font-weight:700;color:var(--brand)}
  .wrap{max-width:1180px;margin:auto;padding:28px 20px 76px}.card{background:var(--card);border:1px solid var(--line);border-radius:22px;padding:22px;box-shadow:var(--shadow)}
  .grid{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(300px,.85fr);gap:18px}.full{grid-column:1/-1}
  h1{margin:0;font-size:32px;letter-spacing:-1px;color:var(--brand)}h2{font-size:17px;margin:0 0 15px;color:var(--brand)}.muted{color:var(--muted)}
  .hero{position:relative;overflow:hidden;background:linear-gradient(135deg,#15263d 0%,#203750 100%);color:#fff;border:0;min-height:260px;padding:28px}
  .hero:after{content:"";position:absolute;width:270px;height:270px;border:55px solid rgba(233,73,76,.18);border-radius:50%;right:-115px;top:-100px}
  .hero:before{content:"";position:absolute;width:150px;height:65px;border:2px solid rgba(255,255,255,.10);border-radius:70% 35% 18% 20%/65% 55% 25% 25%;right:55px;bottom:28px;transform:skewX(-8deg)}
  .hero-inner{position:relative;z-index:2}.eyebrow{font-size:12px;text-transform:uppercase;letter-spacing:.12em;color:#cbd5df;font-weight:800;margin-bottom:12px}
  .hero h1{color:#fff;font-size:34px}.hero-meta{color:#d7dee6;font-size:14px;margin-top:8px}.status-main{display:flex;align-items:center;gap:11px;margin-top:26px;font-size:19px;font-weight:800}
  .status-dot{width:13px;height:13px;background:var(--red);border-radius:50%;box-shadow:0 0 0 6px rgba(233,73,76,.17)}
  .progress-wrap{margin-top:25px}.progress-bar{height:8px;background:rgba(255,255,255,.15);border-radius:20px;overflow:hidden}.progress-bar i{display:block;height:100%;background:var(--red);border-radius:20px}
  .progress-labels{display:flex;justify-content:space-between;margin-top:9px;color:#cbd5df;font-size:12px}.next-step{margin-top:18px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.11);padding:13px 15px;border-radius:14px}
  .next-step small{display:block;color:#bdc8d3;margin-bottom:4px}.next-step b{font-size:14px}
  .mini-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:18px}.mini{background:#f8f9fa;border:1px solid var(--line);border-radius:15px;padding:13px}
  .mini small{display:block;color:var(--muted);font-size:11px;margin-bottom:5px}.mini b{color:var(--brand);font-size:13px}
  .pill{background:var(--green-soft);color:var(--green);padding:7px 10px;border-radius:99px;font-size:12px;font-weight:800}
  .row{display:flex;justify-content:space-between;align-items:flex-start;gap:15px;padding:12px 0;border-bottom:1px solid #edf0f2}.row:last-child{border-bottom:0}.row b{text-align:right}
  .btn{border:0;background:var(--red);color:#fff;border-radius:12px;padding:11px 14px;text-decoration:none;cursor:pointer;font-weight:800;display:inline-block}.btn:hover{filter:brightness(.97)}
  .btn.light{background:#eef1f4;color:var(--brand)}.btn.brand{background:var(--brand)}
  .form{display:grid;gap:10px}.form input,.form select{padding:11px;border:1px solid #dce1e6;border-radius:11px;background:#fff;font:inherit}
  .section-anchor{scroll-margin-top:96px}.stages{display:grid;gap:0}.stage{display:grid;grid-template-columns:28px 1fr;gap:11px;min-height:48px;position:relative}
  .stage:before{content:"";position:absolute;left:8px;top:18px;bottom:0;width:2px;background:#e4e8ec}.stage:last-child:before{display:none}
  .dot{width:18px;height:18px;border-radius:50%;border:2px solid #cfd5da;background:#fff;z-index:1}.done .dot{background:var(--brand);border-color:var(--brand);position:relative}.done .dot:after{content:"✓";font-size:10px;color:#fff;position:absolute;left:3px;top:0}
  .current .dot{border:5px solid var(--red)}.current b{color:var(--red)}.future{color:#9ca4ad}.stage b{font-size:14px}.stage-note{font-size:12px;color:var(--muted);margin-top:3px}
  .journey-groups{display:grid;gap:12px;margin-top:14px}
  .journey-group{border:1px solid var(--line);border-radius:16px;background:#fbfcfd;overflow:hidden}
  .journey-group[open]{background:#fff}
  .journey-group summary{list-style:none;cursor:pointer;padding:15px 16px;display:flex;align-items:center;justify-content:space-between;gap:12px}
  .journey-group summary::-webkit-details-marker{display:none}
  .journey-head{display:flex;align-items:center;gap:11px;min-width:0}
  .journey-num{width:30px;height:30px;border-radius:10px;background:#eef1f4;color:var(--brand);display:grid;place-items:center;font-size:13px;font-weight:900;flex:0 0 auto}
  .journey-group.complete .journey-num{background:var(--green-soft);color:var(--green)}
  .journey-group.active .journey-num{background:var(--red-soft);color:var(--red)}
  .journey-title{font-weight:900;color:var(--brand);font-size:14px}.journey-sub{font-size:11px;color:var(--muted);margin-top:3px}
  .journey-chevron{font-size:16px;color:var(--muted);transition:transform .2s}.journey-group[open] .journey-chevron{transform:rotate(180deg)}
  .journey-body{padding:2px 16px 14px}
  .journey-body .stage{min-height:44px}

  .gallery{display:grid;grid-template-columns:repeat(4,1fr);gap:11px}.thumb{aspect-ratio:4/3;background:#eef1f4;border-radius:14px;display:grid;place-items:center;text-align:center;padding:8px;font-size:12px;overflow:hidden;text-decoration:none;color:var(--brand);font-weight:700}
  .thumb img{width:100%;height:100%;object-fit:cover}.notice{background:#fff8e8;border:1px solid #f4e5b9;padding:13px;border-radius:12px;margin:12px 0;font-size:13px;line-height:1.55}
  .total{font-size:19px;font-weight:900;color:var(--brand)}.doc-status{font-size:12px;font-weight:800}.doc-ok{color:var(--green)}.doc-wait{color:#b57a15}
  .route{display:flex;align-items:center;gap:10px;margin:14px 0 4px}.route-place{flex:1;background:#f7f8fa;border:1px solid var(--line);border-radius:14px;padding:11px}.route-place small{display:block;color:var(--muted);font-size:10px;text-transform:uppercase;font-weight:800;letter-spacing:.06em;margin-bottom:4px}.route-arrow{color:var(--red);font-size:20px;font-weight:900}
  .bottom-nav{display:none}.adminbar{margin-bottom:18px;display:flex;justify-content:space-between;gap:10px}.adminbar a{text-decoration:none}
  .desktop-title{display:block}
  @media(max-width:800px){
    body{padding-bottom:74px}.top{height:66px;padding:0 16px}.brand-logo{width:132px;height:48px}.top-right span{display:none}.wrap{padding:16px 13px 32px}
    .grid{grid-template-columns:1fr;gap:13px}.full{grid-column:auto}.card{border-radius:18px;padding:17px;box-shadow:0 5px 20px rgba(21,38,61,.045)}
    .hero{min-height:0;padding:20px}.hero h1{font-size:27px}.hero-meta{font-size:13px}.status-main{font-size:17px;margin-top:21px}.progress-wrap{margin-top:20px}
    .hero:before{display:none}.hero:after{right:-170px;top:-140px}.mini-grid{grid-template-columns:1fr 1fr}.mini:last-child{grid-column:1/-1}
    .gallery{grid-template-columns:repeat(2,1fr)}.row{font-size:13px}.row b{max-width:58%}.route{gap:6px}.route-place{padding:10px 9px}.route-arrow{font-size:16px}
    .bottom-nav{display:grid;grid-template-columns:repeat(4,1fr);position:fixed;left:0;right:0;bottom:0;background:rgba(255,255,255,.97);border-top:1px solid var(--line);z-index:40;padding-bottom:env(safe-area-inset-bottom);box-shadow:0 -8px 24px rgba(21,38,61,.06)}
    .bottom-nav a{text-decoration:none;text-align:center;font-size:10px;color:var(--muted);padding:9px 3px 8px;font-weight:700}.bottom-nav span{display:block;font-size:18px;margin-bottom:3px}
    .desktop-title{display:none}.adminbar{align-items:center}
  }
  </style></head><body>
  <header class="top">
    <a href="${isAdmin?'/admin':'#top'}"><img class="brand-logo" src="/assets/jpcars-horizontal.svg" alt="JPCars"></a>
    <div class="top-right">${isAdmin?'<a href="/admin/logout">Выйти</a>':'<span>Личный кабинет клиента</span>'}</div>
  </header>
  ${body}
  ${!isAdmin?`<nav class="bottom-nav">
    <a href="#status"><span>🚘</span>Статус</a>
    <a href="#route"><span>📍</span>Маршрут</a>
    <a href="#docs"><span>📄</span>Документы</a>
    <a href="#finance"><span>₽</span>Стоимость</a>
  </nav>`:""}
  </body></html>`;
}


function journeyGroups(country, flow){
  if(country==="Japan"){
    return [
      {title:"Покупка автомобиля", start:0, end:6},
      {title:"Доставка в Россию", start:7, end:12},
      {title:"Оформление и доставка вам", start:13, end:flow.length-1}
    ];
  }
  if(country==="Korea"){
    return [
      {title:"Покупка автомобиля", start:0, end:6},
      {title:"Доставка в Россию", start:7, end:12},
      {title:"Оформление и доставка вам", start:13, end:flow.length-1}
    ];
  }
  return [
    {title:"Покупка автомобиля", start:0, end:6},
    {title:"Доставка в Россию", start:7, end:13},
    {title:"Оформление и доставка вам", start:14, end:flow.length-1}
  ];
}

function renderJourneyGroups(d, flow){
  const groups=journeyGroups(d.country,flow);
  return `<div class="journey-groups">${groups.map((g,idx)=>{
    const total=g.end-g.start+1;
    const completed=Math.max(0,Math.min(total,d.stage-g.start));
    const isComplete=d.stage>g.end;
    const isActive=d.stage>=g.start && d.stage<=g.end;
    const isFuture=d.stage<g.start;
    const doneCount=isComplete?total:(isActive?Math.max(0,d.stage-g.start):0);
    const sub=isComplete
      ? `${total} из ${total} этапов выполнено`
      : isActive
        ? `${doneCount} из ${total} этапов выполнено`
        : `Ещё не начато`;
    return `<details class="journey-group ${isComplete?"complete":isActive?"active":""}" ${isActive?"open":""}>
      <summary>
        <div class="journey-head">
          <div class="journey-num">${isComplete?"✓":idx+1}</div>
          <div><div class="journey-title">${esc(g.title)}</div><div class="journey-sub">${esc(sub)}</div></div>
        </div>
        <div class="journey-chevron">⌄</div>
      </summary>
      <div class="journey-body">
        ${flow.slice(g.start,g.end+1).map((s,offset)=>{
          const i=g.start+offset;
          return `<div class="stage ${i<d.stage?"done":i===d.stage?"current":"future"}">
            <span class="dot"></span>
            <div><b>${esc(s)}</b>${i===d.stage?`<div class="stage-note">${esc(d.current_location||"Текущий этап")}</div>`:""}</div>
          </div>`;
        }).join("")}
      </div>
    </details>`;
  }).join("")}</div>`;
}




async function telegramApi(method,payload={}){
  if(!TELEGRAM_BOT_TOKEN) throw new Error("TELEGRAM_BOT_TOKEN не настроен");
  const response=await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/${method}`,{
    method:"POST",
    headers:{"content-type":"application/json"},
    body:JSON.stringify(payload)
  });
  const data=await response.json();
  if(!response.ok || !data.ok) throw new Error(data.description || `Telegram API error ${response.status}`);
  return data.result;
}

function clientCabinetUrl(d){
  if(PUBLIC_BASE_URL) return `${PUBLIC_BASE_URL}/c/${d.token}`;
  return `/c/${d.token}`;
}

function telegramConnectUrl(d){
  if(!TELEGRAM_BOT_USERNAME) return "";
  return `https://t.me/${TELEGRAM_BOT_USERNAME}?start=${encodeURIComponent(d.token)}`;
}

async function sendTelegramForDeal(d,event,text){
  if(!d.telegram_chat_id || Number(d.telegram_notifications_enabled)===0) return {skipped:true};
  try{
    await telegramApi("sendMessage",{
      chat_id:d.telegram_chat_id,
      text,
      parse_mode:"HTML",
      disable_web_page_preview:true,
      reply_markup:{inline_keyboard:[[{text:"Открыть кабинет",url:clientCabinetUrl(d)}]]}
    });
    db.prepare("INSERT INTO notification_logs(deal_id,channel,event,recipient,success,error) VALUES(?,?,?,?,1,'')")
      .run(d.id,"telegram",event,String(d.telegram_chat_id));
    return {ok:true};
  }catch(e){
    db.prepare("INSERT INTO notification_logs(deal_id,channel,event,recipient,success,error) VALUES(?,?,?,?,0,?)")
      .run(d.id,"telegram",event,String(d.telegram_chat_id||""),String(e.message||e));
    console.error("Telegram send error",e);
    return {ok:false,error:e};
  }
}

function telegramStatusMessage(d,stageTitle,note=""){
  const car=[d.make,d.model].filter(Boolean).join(" ");
  return `🚗 <b>JPCars — обновление по автомобилю</b>

<b>${esc(car||"Ваш автомобиль")}</b>
Новый этап: <b>${esc(stageTitle)}</b>${note?`

${esc(note)}`:""}

Следить за процессом можно в личном кабинете.`;
}

function humanStatusMessage(d,stageTitle,note=""){
  const car=[d.make,d.model].filter(Boolean).join(" ") || "Ваш автомобиль";
  const title=String(stageTitle||"").trim();
  const hints = {
    "Выставлена таможенная пошлина для оплаты":"Таможенная пошлина рассчитана и выставлена к оплате.",
    "Таможенная пошлина оплачена":"Оплата таможенной пошлины получена. Продолжаем оформление автомобиля.",
    "Автомобиль пришел во Владивосток на СВХ":"Автомобиль прибыл во Владивосток и размещён на складе временного хранения.",
    "Автомобиль прошел лабораторию":"Лабораторные процедуры завершены. Переходим к следующему этапу оформления.",
    "Документы ЭПТС и СБКТС получены":"ЭПТС и СБКТС получены. Документальная часть почти завершена.",
    "Автомобиль отправлен из Владивостока до города клиента":"Автомобиль отправлен транспортной компанией в ваш город.",
    "Автомобиль в пути":"Автомобиль находится в пути к вам.",
    "Автомобиль получен":"Автомобиль получен в городе назначения.",
    "Автомобиль готов":"Ваш автомобиль готов. Спасибо, что выбрали JPCars!"
  };
  const body=hints[title] || `Новый этап по вашему автомобилю: ${title}.`;
  return `🚗 <b>JPCars — новости по автомобилю</b>

<b>${esc(car)}</b>
${esc(body)}${note?`

Комментарий менеджера:
${esc(note)}`:""}

Следить за дальнейшим движением можно в личном кабинете.`;
}

async function notifyStaffClientUpload(d,docTitle){
  const staff=db.prepare(`
    SELECT id,name,login,telegram_chat_id,notify_client_uploads
    FROM staff_users
    WHERE active=1 AND telegram_chat_id IS NOT NULL AND notify_client_uploads=1
  `).all();
  const car=[d.make,d.model].filter(Boolean).join(" ") || "Автомобиль";
  for(const u of staff){
    try{
      await telegramApi("sendMessage",{
        chat_id:u.telegram_chat_id,
        text:`📎 <b>JPCars — клиент загрузил документ</b>

Клиент: <b>${esc(d.client_name||"Клиент")}</b>
Автомобиль: <b>${esc(car)}</b>
Документ: <b>${esc(docTitle||"Новый документ")}</b>`,
        parse_mode:"HTML",
        disable_web_page_preview:true,
        reply_markup:{inline_keyboard:[[{text:"Открыть сделку",url:`${PUBLIC_BASE_URL}/admin/deal/${d.id}`}]]}
      });
      db.prepare("INSERT INTO notification_logs(deal_id,channel,event,recipient,success,error) VALUES(?,?,?,?,1,'')")
        .run(d.id,"telegram_staff","client_document_uploaded",String(u.telegram_chat_id));
    }catch(e){
      db.prepare("INSERT INTO notification_logs(deal_id,channel,event,recipient,success,error) VALUES(?,?,?,?,0,?)")
        .run(d.id,"telegram_staff","client_document_uploaded",String(u.telegram_chat_id||""),String(e.message||e));
    }
  }
}

function staffTelegramConnectUrl(user){
  if(!TELEGRAM_BOT_USERNAME) return "";
  return `https://t.me/${TELEGRAM_BOT_USERNAME}?start=staff_${user.id}`;
}

function paymentStatusLabel(status){
  if(status==="paid") return {text:"Оплачено", cls:"doc-ok"};
  if(status==="issued") return {text:"Выставлено", cls:"doc-wait"};
  return {text:"Ожидается", cls:"muted"};
}

function docStatusLabel(doc){
  const status=doc.status||"uploaded";
  if(status==="verified") return {text:"✓ Проверен", cls:"doc-ok"};
  if(status==="replace") return {text:"Нужно заменить", cls:"doc-wait"};
  return {text:"Ожидает проверки", cls:"doc-wait"};
}

function renderDeal(d, isAdmin=false) {
  const flow = FLOWS[d.country];
  const docs = db.prepare("SELECT * FROM documents WHERE deal_id=? ORDER BY id DESC").all(d.id);
  const media = db.prepare("SELECT * FROM media WHERE deal_id=? ORDER BY id DESC").all(d.id);
  const events = db.prepare("SELECT * FROM events WHERE deal_id=? ORDER BY id DESC").all(d.id);
  const payments = db.prepare("SELECT * FROM payments WHERE deal_id=? ORDER BY id ASC").all(d.id);
  const total = d.car_price + d.country_costs + d.delivery + d.customs_duty + d.customs_clearance + d.commission;
  const requiredDocs=DOC_RULES[d.country];
  const completedRequired=requiredDocs.filter(cat=>docs.some(x=>x.category===cat && (x.status||"uploaded")!=="replace")).length;
  const docProgress=Math.round((completedRequired/requiredDocs.length)*100);

  const progress = Math.round(((d.stage + 1) / flow.length) * 100);
  const nextStage = d.stage < flow.length - 1 ? flow[d.stage + 1] : "Все этапы завершены";

  const docOptions = [
    ...DOC_RULES[d.country],
    "Аукционный лист / объявление",
    "Агентский договор",
    "Таможенные документы",
    "Квитанция об оплате таможни",
    "ЭПТС",
    "СБКТС"
  ];

  const routeFrom = d.departure_place || COUNTRY_NAMES[d.country];
  const routeTo = d.arrival_place || (d.country === "China" ? "Уссурийск" : "Владивосток");

  return `<main class="wrap" id="top">
    ${isAdmin?`<div class="adminbar"><a href="/admin">← Все сделки</a><div style="display:flex;gap:8px"><a class="btn light" href="/c/${d.token}" target="_blank">Кабинет клиента</a><a class="btn brand" href="/admin/edit/${d.id}">Редактировать карточку</a></div></div>`:""}

    ${!isAdmin?`<section class="card hero section-anchor" id="status">
      <div class="hero-inner">
        <div class="eyebrow">${esc(COUNTRY_NAMES[d.country])} · Ваш автомобиль</div>
        <h1>${esc(d.make)} ${esc(d.model)}</h1>
        <div class="hero-meta">${d.year||""} год · ${d.mileage?Number(d.mileage).toLocaleString("ru-RU")+" км · ":""}${esc(d.vin||"VIN / номер кузова уточняется")}</div>
        <div class="status-main"><span class="status-dot"></span><span>${esc(flow[d.stage])}</span></div>
        <div class="progress-wrap">
          <div class="progress-bar"><i style="width:${progress}%"></i></div>
          <div class="progress-labels"><span>Начало заказа</span><span>${progress}%</span><span>Автомобиль готов</span></div>
        </div>
        <div class="next-step"><small>Следующий этап</small><b>${esc(nextStage)}</b></div>
      </div>
    </section>

    <div class="mini-grid">
      <div class="mini"><small>Текущая локация</small><b>${esc(d.current_location||"Уточняется")}</b></div>
      <div class="mini"><small>Ожидаемое прибытие</small><b>${esc(d.eta||"Уточняется")}</b></div>
      <div class="mini"><small>Страна покупки</small><b>${esc(COUNTRY_NAMES[d.country])}</b></div>
    </div>`:`
    <div style="display:flex;justify-content:space-between;gap:15px;align-items:end;margin-bottom:22px">
      <div><h1>${esc(d.make)} ${esc(d.model)}</h1>
      <div class="muted">${esc(COUNTRY_NAMES[d.country])} · ${d.year||""} · ${d.mileage?Number(d.mileage).toLocaleString("ru-RU")+" км":""} · ${esc(d.vin||"")}</div></div>
      <span class="pill">${esc(flow[d.stage])}</span>
    </div>`}

    <div class="grid" style="margin-top:18px">
      <section class="card section-anchor" id="route">
        <h2>${isAdmin?"Путь автомобиля":"🚘 Путь автомобиля"}</h2>
        ${!isAdmin?`<div class="route">
          <div class="route-place"><small>Отправление</small><b>${esc(routeFrom)}</b></div>
          <div class="route-arrow">→</div>
          <div class="route-place"><small>Прибытие</small><b>${esc(routeTo)}</b></div>
        </div>`:""}
        ${isAdmin?`<div class="stages" style="margin-top:18px">
        ${flow.map((s,i)=>`<div class="stage ${i<d.stage?"done":i===d.stage?"current":"future"}">
          <span class="dot"></span><div><b>${esc(s)}</b>${i===d.stage?`<div class="stage-note">${esc(d.current_location||"Текущий этап")}</div>`:""}</div>
        </div>`).join("")}
        </div>`:renderJourneyGroups(d,flow)}
      </section>

      <div style="display:grid;gap:18px;align-content:start">
        <section class="card">
          <h2>🚗 Автомобиль</h2>
          <div class="row"><span class="muted">Клиент</span><b>${esc(d.client_name)}</b></div>
          <div class="row"><span class="muted">Марка / модель</span><b>${esc(d.make)} ${esc(d.model)}</b></div>
          <div class="row"><span class="muted">Год</span><b>${esc(d.year||"—")}</b></div>
          <div class="row"><span class="muted">VIN / кузов</span><b>${esc(d.vin||"—")}</b></div>
          <div class="row"><span class="muted">Пробег</span><b>${d.mileage?Number(d.mileage).toLocaleString("ru-RU")+" км":"—"}</b></div>
          <div class="row"><span class="muted">Дата покупки</span><b>${esc(d.purchase_date||"—")}</b></div>
          <div class="row"><span class="muted">Стоимость при покупке</span><b>${money(d.expected_price)}</b></div>
        </section>

        <section class="card">
          <h2>📍 Логистика</h2>
          <div class="row"><span class="muted">Сейчас</span><b>${esc(d.current_location||"—")}</b></div>
          <div class="row"><span class="muted">${d.country==="China"?"Город отправки":"Порт отправления"}</span><b>${esc(d.departure_place||"—")}</b></div>
          <div class="row"><span class="muted">Дата отправки</span><b>${esc(d.departure_date||"—")}</b></div>
          <div class="row"><span class="muted">Ожидаемое прибытие</span><b>${esc(d.eta||"—")}</b></div>
          <div class="row"><span class="muted">${d.country==="China"?"Город прибытия":"Порт прибытия"}</span><b>${esc(d.arrival_place||"—")}</b></div>
          ${(d.country==="Japan"||d.country==="Korea")&&d.tracking_url?`<a class="btn brand" style="display:block;text-align:center;margin-top:14px" href="${esc(d.tracking_url)}" target="_blank">⚓ Отследить корабль</a>`:""}
        </section>

        <section class="card section-anchor" id="finance">
          <h2>₽ Стоимость</h2>
          ${[
            ["Автомобиль",d.car_price],
            ["Расходы по стране",d.country_costs],
            ["Доставка до России",d.delivery],
            ["Таможенная пошлина",d.customs_duty],
            ["Таможенное оформление",d.customs_clearance],
            ["Комиссия JPCars",d.commission]
          ].map(x=>`<div class="row"><span>${x[0]}</span><b>${money(x[1])}</b></div>`).join("")}
          <div class="row"><span class="total">Итого</span><span class="total">${money(total)}</span></div>
        </section>
      </div>

      <section class="card full section-anchor" id="media">
        <h2>📸 Фото и видео автомобиля</h2>
        <div class="gallery">
          ${media.map(m=>`<div>${m.kind==="image"
            ? `<a class="thumb" href="${isAdmin?`/admin/media-file/${m.id}`:`/c/${d.token}/media/${m.id}`}" target="_blank"><img src="${isAdmin?`/admin/media-file/${m.id}`:`/c/${d.token}/media/${m.id}`}" alt="${esc(m.caption||m.original_name)}"></a>`
            : `<a class="thumb" href="${isAdmin?`/admin/media-file/${m.id}`:`/c/${d.token}/media/${m.id}`}" target="_blank">▶ ${esc(m.caption||m.original_name)}</a>`}
            ${isAdmin?`<form method="post" action="/admin/media/${m.id}/delete" style="margin-top:6px" onsubmit="return confirm('Удалить файл?')"><button class="btn light" style="width:100%" type="submit">Удалить</button></form>`:""}
            </div>`).join("") || '<div class="muted">Как только менеджер загрузит фотографии или видео, они появятся здесь.</div>'}
        </div>
        ${isAdmin?`<form class="form" style="margin-top:14px" action="/admin/media/${d.id}" method="post" enctype="multipart/form-data">
          <input type="file" name="media" multiple required>
          <input name="caption" placeholder="Подпись, например: Стоянка Тояма">
          <button class="btn">Загрузить фото / видео</button>
        </form>`:""}
      </section>

      <section class="card full section-anchor" id="docs">
        <h2>📄 Документы</h2>
        <div style="margin-bottom:14px">
          <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:7px"><b>${completedRequired} из ${requiredDocs.length} необходимых документов</b><span class="muted">${docProgress}%</span></div>
          <div style="height:7px;background:#edf0f2;border-radius:10px;overflow:hidden"><i style="display:block;height:100%;width:${docProgress}%;background:var(--red);border-radius:10px"></i></div>
        </div>
        <div class="notice"><b>Что потребуется по вашему заказу:</b><br>${DOC_RULES[d.country].map(esc).join(" · ")}</div>
        ${docs.map(x=>{const ds=docStatusLabel(x);return `<div class="row">
          <div><span>📄 <a href="${isAdmin?`/admin/doc-file/${x.id}`:`/c/${d.token}/doc/${x.id}`}">${esc(x.category)} — ${esc(x.original_name)}</a></span>
          ${x.manager_comment?`<div class="muted" style="font-size:12px;margin-top:5px">Комментарий: ${esc(x.manager_comment)}</div>`:""}</div>
          <span style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;justify-content:flex-end">
            <span class="doc-status ${ds.cls}">${ds.text}</span>
            ${isAdmin?`<form method="post" action="/admin/doc/${x.id}/status" style="display:flex;gap:5px;flex-wrap:wrap">
              <select name="status" style="padding:8px;border:1px solid var(--line);border-radius:9px">
                <option value="uploaded" ${(x.status||"uploaded")==="uploaded"?"selected":""}>На проверке</option>
                <option value="verified" ${(x.status||"uploaded")==="verified"?"selected":""}>Проверен</option>
                <option value="replace" ${(x.status||"uploaded")==="replace"?"selected":""}>Нужно заменить</option>
              </select>
              <input name="manager_comment" value="${esc(x.manager_comment||"")}" placeholder="Комментарий" style="padding:8px;border:1px solid var(--line);border-radius:9px;max-width:220px">
              <button class="btn light" type="submit">Сохранить</button>
            </form>`:""}
            ${isAdmin?`<form method="post" action="/admin/doc/${x.id}/delete" style="display:inline" onsubmit="return confirm('Удалить документ?')"><button class="btn light" type="submit">Удалить</button></form>`:""}
          </span>
        </div>`}).join("") || '<p class="muted">Загруженных документов пока нет.</p>'}

        <form class="form" style="margin-top:14px" action="${isAdmin?"/admin/doc/"+d.id:"/c/"+d.token+"/doc"}" method="post" enctype="multipart/form-data">
          <select name="category">${docOptions.map(x=>`<option>${esc(x)}</option>`).join("")}</select>
          <input type="file" name="document" required>
          <button class="btn">${isAdmin?"Загрузить документ":"Добавить документ"}</button>
        </form>
        ${isAdmin?`<a class="btn light" style="display:inline-block;margin-top:12px" href="/admin/broker/${d.id}">📦 Пакет для брокера</a>`:""}
      </section>

      ${!isAdmin?`<section class="card full">
        <h2>✈️ Telegram-уведомления</h2>
        ${d.telegram_chat_id
          ? `<div class="row"><div><b>Telegram подключён</b><div class="muted" style="font-size:12px;margin-top:4px">${d.telegram_first_name?esc(d.telegram_first_name):"Клиент"}${d.telegram_username?` · @${esc(d.telegram_username)}`:""}</div></div><span class="doc-status doc-ok">✓ Активно</span></div>
             <p class="muted" style="font-size:13px">Мы будем присылать уведомления при изменении этапа автомобиля.</p>`
          : TELEGRAM_BOT_USERNAME
            ? `<p class="muted">Подключите Telegram, чтобы получать уведомления при изменении статуса автомобиля.</p>
               <a class="btn brand" href="${telegramConnectUrl(d)}" target="_blank">Подключить Telegram</a>`
            : `<p class="muted">Telegram-уведомления пока не настроены.</p>`}
      </section>`:""}

      <section class="card full section-anchor" id="payments">
        <h2>💳 Платежи</h2>
        ${payments.length?payments.map(p=>{const ps=paymentStatusLabel(p.status);return `<div class="row">
          <div><b>${esc(p.title)}</b><div class="muted" style="font-size:12px;margin-top:4px">${esc(p.note||"")}</div></div>
          <div style="text-align:right"><b>${money(p.amount)}</b><div class="doc-status ${ps.cls}" style="margin-top:4px">${ps.text}</div>
          ${p.document_stored?`<div style="margin-top:5px"><a href="${isAdmin?`/admin/payment-file/${p.id}`:`/c/${d.token}/payment/${p.id}`}">Документ</a></div>`:""}</div>
        </div>`}).join(""):'<p class="muted">Платежи пока не добавлены.</p>'}
        ${isAdmin?`<form class="form" method="post" action="/admin/payment/${d.id}/new" enctype="multipart/form-data" style="margin-top:14px">
          <input name="title" placeholder="Название платежа" required>
          <input name="amount" type="number" placeholder="Сумма, ₽" required>
          <select name="status"><option value="expected">Ожидается</option><option value="issued">Выставлено</option><option value="paid">Оплачено</option></select>
          <input name="note" placeholder="Комментарий">
          <input type="file" name="document">
          <button class="btn">Добавить платеж</button>
        </form>`:""}
      </section>

      <section class="card full">
        <h2>🕘 История заказа</h2>
        ${events.map(e=>`<div class="row"><div><b>${esc(e.title)}</b><div class="muted" style="font-size:12px;margin-top:4px">${esc(e.note||"")}</div></div>
        <span class="muted">${new Date(e.created_at+"Z").toLocaleDateString("ru-RU")}</span></div>`).join("")}
      </section>

      ${isAdmin?`<section class="card full">
        <h2>✈️ Telegram клиента</h2>
        <div class="row"><span class="muted">Статус</span><b>${d.telegram_chat_id?"Подключён":"Не подключён"}</b></div>
        ${d.telegram_chat_id?`
          <div class="row"><span class="muted">Получатель</span><b>${esc(d.telegram_first_name||"Telegram")}${d.telegram_username?` · @${esc(d.telegram_username)}`:""}</b></div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px">
            <form method="post" action="/admin/telegram/${d.id}/test"><button class="btn brand" type="submit">Отправить тест</button></form>
            <form method="post" action="/admin/telegram/${d.id}/toggle-notifications"><button class="btn light" type="submit">${Number(d.telegram_notifications_enabled)===0?"Включить автоуведомления":"Отключить автоуведомления"}</button></form>
            <form method="post" action="/admin/telegram/${d.id}/disconnect" onsubmit="return confirm('Отключить Telegram клиента?')"><button class="btn light" type="submit">Отключить</button></form>
          </div>
          <form class="form" method="post" action="/admin/telegram/${d.id}/message" style="margin-top:14px">
            <textarea name="message" rows="3" placeholder="Написать клиенту в Telegram..." maxlength="3500" required></textarea>
            <button class="btn brand" type="submit">Отправить сообщение клиенту</button>
          </form>`
          : TELEGRAM_BOT_USERNAME
            ? `<p class="muted">Клиент должен открыть кнопку «Подключить Telegram» в своём кабинете.</p>`
            : `<p class="muted">Добавьте TELEGRAM_BOT_TOKEN и TELEGRAM_BOT_USERNAME в Railway Variables.</p>`}
      </section>`:""}

      ${isAdmin?`<section class="card full">
        <h2>🔐 Доступ клиента</h2>
        <div class="row"><span class="muted">Статус ссылки</span><b>${d.access_enabled!==0?"Активна":"Отключена"}</b></div>
        <div class="row"><span class="muted">Персональная ссылка</span><b style="word-break:break-all">/c/${esc(d.token)}</b></div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:14px">
          <a class="btn brand" href="/c/${d.token}" target="_blank">Открыть кабинет</a>
          <form method="post" action="/admin/access/${d.id}/toggle"><button class="btn light" type="submit">${d.access_enabled!==0?"Отключить ссылку":"Включить ссылку"}</button></form>
          <form method="post" action="/admin/access/${d.id}/regenerate" onsubmit="return confirm('Старая ссылка перестанет работать. Сгенерировать новую?')"><button class="btn light" type="submit">Сгенерировать новую</button></form>
        </div>
      </section>`:""}

      ${isAdmin?`<section class="card full">
        <h2>🛡️ Журнал доступа</h2>
        ${db.prepare("SELECT * FROM access_logs WHERE deal_id=? ORDER BY id DESC LIMIT 20").all(d.id).map(l=>`<div class="row">
          <div><b>${esc(l.actor)} · ${esc(l.action)}</b><div class="muted" style="font-size:12px;margin-top:4px">${esc(l.resource_type)}${l.resource_id?` #${l.resource_id}`:""} · ${esc(l.ip||"")}</div></div>
          <span class="muted">${new Date(l.created_at+"Z").toLocaleString("ru-RU")}</span>
        </div>`).join("") || '<p class="muted">Записей пока нет.</p>'}
      </section>`:""}

      ${isAdmin?`<section class="card full">
        <h2>🔔 История уведомлений</h2>
        ${db.prepare("SELECT * FROM notification_logs WHERE deal_id=? ORDER BY id DESC LIMIT 20").all(d.id).map(n=>`<div class="row">
          <div><b>${n.success?"✓":"✕"} ${esc(n.channel)} · ${esc(n.event)}</b><div class="muted" style="font-size:12px;margin-top:4px">${esc(n.recipient||"")}${n.error?` · ${esc(n.error)}`:""}</div></div>
          <span class="muted">${new Date(n.created_at+"Z").toLocaleString("ru-RU")}</span>
        </div>`).join("") || '<p class="muted">Уведомлений пока нет.</p>'}
      </section>

      <section class="card full">
        <h2>📦 Архив сделки</h2>
        <div class="row"><span class="muted">Статус</span><b>${d.archived?"В архиве":"Активная сделка"}</b></div>
        <form method="post" action="/admin/archive/${d.id}/toggle" style="margin-top:12px"><button class="btn light" type="submit">${d.archived?"Вернуть в активные":"Переместить в архив"}</button></form>
      </section>`:""}

      ${isAdmin?`<section class="card full">
        <h2>Управление сделкой</h2>
        <form class="form" action="/admin/update/${d.id}" method="post">
          <select name="stage">${flow.map((x,i)=>`<option value="${i}" ${i===d.stage?"selected":""}>${i+1}. ${esc(x)}</option>`).join("")}</select>
          <input name="current_location" value="${esc(d.current_location||"")}" placeholder="Текущая локация">
          <input name="departure_place" value="${esc(d.departure_place||"")}" placeholder="Порт / город отправления">
          <input name="tracking_url" value="${esc(d.tracking_url||"")}" placeholder="Ссылка отслеживания">
          <input name="departure_date" type="date" value="${esc(d.departure_date||"")}">
          <input name="eta" type="date" value="${esc(d.eta||"")}">
          <input name="arrival_place" value="${esc(d.arrival_place||"")}" placeholder="Порт / город прибытия">
          <input name="note" placeholder="Комментарий для истории">
          <label style="display:flex;align-items:center;gap:8px;font-size:13px"><input type="checkbox" name="silent_telegram" value="1" style="width:auto"> Не отправлять Telegram-уведомление клиенту для этого изменения</label><button class="btn">Сохранить изменения</button>
        </form>
      </section>`:""}
    </div>
  </main>`;
}

app.get("/c/:token",publicLimiter,(req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE token=? AND access_enabled=1").get(req.params.token);
  if(!d) return res.status(404).send("Ссылка недействительна или доступ отключён");
  res.send(shell("Ваш автомобиль",renderDeal(d,false),false));
});


app.get("/healthz",(_req,res)=>res.status(200).json({ok:true,service:"jpcars",version:"1.2.0"}));

app.get("/",(_req,res)=>res.redirect("/admin"));

app.get("/admin/login",(req,res)=>{
  res.send(shell("Вход",`<main class="wrap" style="max-width:430px"><div class="card">
    <h1>Админка JPCars</h1>
    <form class="form" method="post"><input name="login" placeholder="Логин" required>
    <input type="password" name="password" placeholder="Пароль" required>
    <button class="btn">Войти</button></form>
    ${IS_PROD?"":`<p class="muted">Локально: admin / change-me</p>`}
  </div></main>`));
});

app.post("/admin/login",loginLimiter,(req,res)=>{
  const login=String(req.body.login||"").trim();
  const password=String(req.body.password||"");
  const user=db.prepare("SELECT * FROM staff_users WHERE login=? AND active=1").get(login);
  if(user && verifyPassword(password,user.password_salt,user.password_hash)){
    req.session.staffId=user.id;
    audit(req,{type:"auth",actor:`${user.name} (${user.login})`,action:"login_success"});
    return res.redirect("/admin");
  }
  audit(req,{type:"auth",actor:login||"anonymous",action:"login_failed"});
  res.status(401).send("Неверный логин или пароль");
});

const admin=(req,res,next)=>{
  const u=currentStaff(req);
  if(!u) return res.redirect("/admin/login");
  req.staff=u;
  next();
};
const superAdmin=(req,res,next)=>{
  const u=currentStaff(req);
  if(!u) return res.redirect("/admin/login");
  if(u.role!=="admin") return res.status(403).send("Недостаточно прав");
  req.staff=u;
  next();
};

app.post("/telegram/webhook",async (req,res)=>{
  console.log("Telegram webhook received", new Date().toISOString());
  if(!TELEGRAM_BOT_TOKEN) return res.sendStatus(404);
  if(TELEGRAM_WEBHOOK_SECRET){
    const secret=req.get("x-telegram-bot-api-secret-token")||"";
    if(secret!==TELEGRAM_WEBHOOK_SECRET) return res.sendStatus(403);
  }
  res.sendStatus(200);

  try{
    const msg=req.body?.message;
    if(!msg || msg.chat?.type!=="private" || !msg.text) return;
    const match=msg.text.match(/^\/start(?:@\w+)?(?:\s+([A-Za-z0-9_-]{8,64}))?/);
    if(!match) return;
    const token=match[1];
    if(!token){
      await telegramApi("sendMessage",{chat_id:msg.chat.id,text:"Откройте кнопку подключения Telegram в JPCars."});
      return;
    }

    if(token.startsWith("staff_")){
      const staffId=Number(token.slice(6));
      const u=db.prepare("SELECT * FROM staff_users WHERE id=? AND active=1").get(staffId);
      if(!u){
        await telegramApi("sendMessage",{chat_id:msg.chat.id,text:"Ссылка сотрудника JPCars недействительна."});
        return;
      }
      db.prepare(`UPDATE staff_users SET telegram_chat_id=?,telegram_username=?,telegram_first_name=?,telegram_connected_at=CURRENT_TIMESTAMP WHERE id=?`)
        .run(String(msg.chat.id),msg.from?.username||"",msg.from?.first_name||"",u.id);
      await telegramApi("sendMessage",{
        chat_id:msg.chat.id,
        text:`✅ Telegram сотрудника JPCars подключён.\n\nТеперь сюда будут приходить служебные уведомления.`
      });
      return;
    }

    const d=db.prepare("SELECT * FROM deals WHERE token=? AND access_enabled=1").get(token);
    if(!d){
      await telegramApi("sendMessage",{chat_id:msg.chat.id,text:"Ссылка JPCars недействительна или доступ к сделке отключён."});
      return;
    }
    db.prepare(`UPDATE deals SET telegram_chat_id=?,telegram_username=?,telegram_first_name=?,telegram_connected_at=CURRENT_TIMESTAMP WHERE id=?`)
      .run(String(msg.chat.id),msg.from?.username||"",msg.from?.first_name||"",d.id);
    db.prepare("INSERT INTO notification_logs(deal_id,channel,event,recipient,success,error) VALUES(?,?,?,?,1,'')")
      .run(d.id,"telegram","connected",String(msg.chat.id));
    const updated=db.prepare("SELECT * FROM deals WHERE id=?").get(d.id);
    await telegramApi("sendMessage",{
      chat_id:msg.chat.id,
      text:`✅ Telegram подключён к вашему заказу JPCars.\n\nТеперь мы будем сообщать об изменении этапов автомобиля.`,
      reply_markup:{inline_keyboard:[[{text:"Открыть кабинет",url:clientCabinetUrl(updated)}]]}
    });
  }catch(e){ console.error("Telegram webhook error",e); }
});

app.post("/admin/telegram/:id/test",admin,async (req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE id=?").get(req.params.id);
  if(!d) return res.sendStatus(404);
  await sendTelegramForDeal(d,"test",`✅ <b>Тестовое уведомление JPCars</b>\n\nTelegram успешно подключён к ${esc([d.make,d.model].filter(Boolean).join(" ")||"вашему автомобилю")}.`);
  audit(req,{dealId:d.id,type:"telegram",resourceId:d.id,action:"test_notification"});
  res.redirect("/admin/deal/"+d.id);
});


app.post("/admin/telegram/:id/message",admin,async (req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE id=?").get(req.params.id);
  if(!d) return res.sendStatus(404);
  const message=String(req.body.message||"").trim().slice(0,3500);
  if(!message) return res.status(400).send("Введите сообщение");
  const body=`💬 <b>Сообщение от JPCars</b>

${esc(message)}`;
  await sendTelegramForDeal(d,"manual_message",body);
  audit(req,{dealId:d.id,type:"telegram",resourceId:d.id,action:"manual_message"});
  res.redirect("/admin/deal/"+d.id);
});

app.post("/admin/telegram/:id/toggle-notifications",admin,(req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE id=?").get(req.params.id);
  if(!d) return res.sendStatus(404);
  const next=Number(d.telegram_notifications_enabled)===0?1:0;
  db.prepare("UPDATE deals SET telegram_notifications_enabled=? WHERE id=?").run(next,d.id);
  audit(req,{dealId:d.id,type:"telegram",resourceId:d.id,action:next?"notifications_enable":"notifications_disable"});
  res.redirect("/admin/deal/"+d.id);
});

app.post("/admin/telegram/:id/disconnect",admin,(req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE id=?").get(req.params.id);
  if(!d) return res.sendStatus(404);
  db.prepare("UPDATE deals SET telegram_chat_id=NULL,telegram_username=NULL,telegram_first_name=NULL,telegram_connected_at=NULL WHERE id=?").run(d.id);
  audit(req,{dealId:d.id,type:"telegram",resourceId:d.id,action:"disconnect"});
  res.redirect("/admin/deal/"+d.id);
});

app.get("/admin/telegram-setup",superAdmin,(req,res)=>{
  res.send(shell("Telegram",`<main class="wrap">
    <div class="adminbar"><div><h1>Telegram JPCars</h1><div class="muted">Webhook, клиентские и служебные уведомления</div></div><a href="/admin">← Сделки</a></div>
    <div class="card">
      <div class="row"><span>Bot username</span><b>${TELEGRAM_BOT_USERNAME?`@${esc(TELEGRAM_BOT_USERNAME)}`:"Не задан"}</b></div>
      <div class="row"><span>Bot token</span><b>${TELEGRAM_BOT_TOKEN?"Задан":"Не задан"}</b></div>
      <div class="row"><span>Public URL</span><b>${esc(PUBLIC_BASE_URL||"Не задан")}</b></div>
      <div class="row"><span>Webhook secret</span><b>${TELEGRAM_WEBHOOK_SECRET?"Задан":"Не задан"}</b></div>
      <form method="post" action="/admin/telegram-setup" style="margin-top:15px"><button class="btn brand">Установить webhook</button></form>
    </div>
  </main>`,true));
});

app.post("/admin/telegram-setup",superAdmin,async (req,res)=>{
  if(!TELEGRAM_BOT_TOKEN || !PUBLIC_BASE_URL) return res.status(400).send("Не заданы TELEGRAM_BOT_TOKEN или PUBLIC_BASE_URL");
  try{
    const payload={url:`${PUBLIC_BASE_URL}/telegram/webhook`,allowed_updates:["message"]};
    if(TELEGRAM_WEBHOOK_SECRET) payload.secret_token=TELEGRAM_WEBHOOK_SECRET;
    await telegramApi("setWebhook",payload);
    audit(req,{type:"telegram",action:"set_webhook"});
    res.redirect("/admin/telegram-setup");
  }catch(e){ res.status(500).send(`Telegram webhook error: ${esc(e.message)}`); }
});


app.get("/admin/logout",(req,res)=>{
  audit(req,{type:"auth",action:"logout"});
  req.session.destroy(()=>res.redirect("/admin/login"));
});

app.get("/admin",admin,(req,res)=>{
  const q=(req.query.q||"").trim().toLowerCase();
  const country=req.query.country||"";
  const archive=req.query.archive==="1";
  let deals=db.prepare("SELECT * FROM deals ORDER BY id DESC").all();

  deals=deals.filter(d=>{
    if((d.archived||0)!==(archive?1:0)) return false;
    if(country && d.country!==country) return false;
    if(q){
      const hay=[d.client_name,d.client_phone,d.make,d.model,d.vin].map(x=>String(x||"").toLowerCase()).join(" ");
      if(!hay.includes(q)) return false;
    }
    return true;
  });

  const all=db.prepare("SELECT * FROM deals").all();
  const stats={
    active:all.filter(d=>(d.archived||0)===0).length,
    archive:all.filter(d=>(d.archived||0)===1).length,
    japan:all.filter(d=>d.country==="Japan"&&(d.archived||0)===0).length,
    korea:all.filter(d=>d.country==="Korea"&&(d.archived||0)===0).length,
    china:all.filter(d=>d.country==="China"&&(d.archived||0)===0).length
  };

  res.send(shell("Сделки",`<main class="wrap">
    <div class="adminbar">
      <div><h1>${archive?"Архив сделок":"Сделки JPCars"}</h1><div class="muted">${archive?"Завершённые сделки":"Рабочая панель менеджера"}</div></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">${req.staff?.role==="admin"?`<a class="btn light" href="/admin/team">Команда</a><a class="btn light" href="/admin/telegram-setup">Telegram</a>`:""}<a class="btn light" href="/admin?archive=${archive?0:1}">${archive?"Активные сделки":"Архив"}</a><a class="btn" href="/admin/new">+ Новая сделка</a></div>
    </div>

    <div class="mini-grid" style="margin-bottom:18px">
      <div class="mini"><small>Активные</small><b>${stats.active}</b></div>
      <div class="mini"><small>В архиве</small><b>${stats.archive}</b></div>
      <div class="mini"><small>Страны</small><b>🇯🇵 ${stats.japan} · 🇰🇷 ${stats.korea} · 🇨🇳 ${stats.china}</b></div>
    </div>

    <div class="card" style="margin-bottom:18px">
      <form method="get" class="form" style="grid-template-columns:2fr 1fr auto;align-items:end">
        <input type="hidden" name="archive" value="${archive?1:0}">
        <input name="q" value="${esc(req.query.q||"")}" placeholder="Поиск: ФИО, телефон, VIN, марка, модель">
        <select name="country">
          <option value="">Все страны</option>
          <option value="Japan" ${country==="Japan"?"selected":""}>Япония</option>
          <option value="Korea" ${country==="Korea"?"selected":""}>Южная Корея</option>
          <option value="China" ${country==="China"?"selected":""}>Китай</option>
        </select>
        <button class="btn brand">Найти</button>
      </form>
    </div>

    <div class="card">
      ${deals.map(d=>{
        const flow=FLOWS[d.country], progress=Math.round(((d.stage+1)/flow.length)*100);
        return `<div class="row" style="align-items:center">
          <div style="min-width:0">
            <b>${esc(d.client_name)}</b>
            <div class="muted" style="margin-top:4px">${esc(d.make||"")} ${esc(d.model||"")} · ${esc(COUNTRY_NAMES[d.country])}</div>
            <div class="muted" style="font-size:12px;margin-top:3px">${esc(d.client_phone||"")} ${d.vin?`· ${esc(d.vin)}`:""}</div>
            <div style="margin-top:7px;height:5px;background:#edf0f2;border-radius:9px;overflow:hidden;max-width:340px"><i style="display:block;width:${progress}%;height:100%;background:var(--red)"></i></div>
            <div class="muted" style="font-size:11px;margin-top:4px">${progress}% · ${esc(flow[d.stage])}</div>
          </div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;justify-content:flex-end">
            <a class="btn light" href="/c/${d.token}" target="_blank">Клиент</a>
            <a class="btn brand" href="/admin/deal/${d.id}">Управление</a>
          </div>
        </div>`;
      }).join("") || '<p class="muted">Ничего не найдено.</p>'}
    </div>
  </main>`,true));
});
app.get("/admin/deal/:id",admin,(req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE id=?").get(req.params.id);
  if(!d) return res.sendStatus(404);
  res.send(shell("Сделка",renderDeal(d,true),true));
});

app.post("/admin/update/:id",admin,async (req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE id=?").get(req.params.id);
  if(!d) return res.sendStatus(404);
  const stage=Math.max(0,Math.min(Number(req.body.stage)||0,FLOWS[d.country].length-1));
  db.prepare(`UPDATE deals SET stage=?,current_location=?,departure_place=?,tracking_url=?,departure_date=?,eta=?,arrival_place=? WHERE id=?`)
    .run(stage,req.body.current_location,req.body.departure_place,req.body.tracking_url,req.body.departure_date,req.body.eta,req.body.arrival_place,d.id);
  db.prepare("INSERT INTO events(deal_id,title,note) VALUES(?,?,?)")
    .run(d.id,FLOWS[d.country][stage],req.body.note||"Статус сделки обновлён.");
  res.redirect("/admin/deal/"+d.id);
});

app.get("/admin/new",admin,(req,res)=>{
  res.send(shell("Новая сделка",`<main class="wrap">
    <div class="adminbar"><div><h1>Новая сделка</h1><div class="muted">Создание клиента и автомобиля</div></div><a href="/admin">← Назад</a></div>
    <div class="card">
      <form class="form" method="post">
        <h2>Клиент</h2>
        <input name="client_name" placeholder="ФИО клиента" required>
        <input name="client_phone" placeholder="Телефон">
        <h2 style="margin-top:10px">Автомобиль</h2>
        <select name="country"><option value="Japan">Япония</option><option value="Korea">Южная Корея</option><option value="China">Китай</option></select>
        <input name="make" placeholder="Марка" required>
        <input name="model" placeholder="Модель" required>
        <input name="year" type="number" placeholder="Год выпуска">
        <input name="vin" placeholder="VIN / номер кузова">
        <input name="mileage" type="number" placeholder="Пробег, км">
        <input name="expected_price" type="number" placeholder="Предполагаемая стоимость автомобиля, ₽">
        <h2 style="margin-top:10px">Комментарий менеджера</h2>
        <input name="manager_note" placeholder="Внутренняя заметка (клиент её не видит)">
        <button class="btn">Создать сделку</button>
      </form>
    </div>
  </main>`,true));
});
app.post("/admin/new",admin,(req,res)=>{
  const token=crypto.randomBytes(24).toString("base64url");
  const r=db.prepare(`INSERT INTO deals(token,client_name,client_phone,country,make,model,year,vin,mileage,expected_price,manager_note)
  VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(
    token,req.body.client_name,req.body.client_phone,req.body.country,req.body.make,req.body.model,
    req.body.year||null,req.body.vin,req.body.mileage||null,req.body.expected_price||0,req.body.manager_note||""
  );
  db.prepare("INSERT INTO events(deal_id,title,note) VALUES(?,?,?)").run(Number(r.lastInsertRowid),"Консультация","Сделка создана.");
  res.redirect("/admin/deal/"+Number(r.lastInsertRowid));
});

app.get("/admin/edit/:id",admin,(req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE id=?").get(req.params.id);
  if(!d) return res.sendStatus(404);
  res.send(shell("Редактирование сделки",`<main class="wrap">
    <div class="adminbar"><div><h1>Редактирование сделки</h1><div class="muted">${esc(d.client_name)} · ${esc(d.make)} ${esc(d.model)}</div></div><a href="/admin/deal/${d.id}">← К сделке</a></div>
    <div class="grid">
      <section class="card">
        <h2>Клиент и автомобиль</h2>
        <form class="form" method="post">
          <input name="client_name" value="${esc(d.client_name||"")}" placeholder="ФИО клиента">
          <input name="client_phone" value="${esc(d.client_phone||"")}" placeholder="Телефон">
          <select name="country">
            <option value="Japan" ${d.country==="Japan"?"selected":""}>Япония</option>
            <option value="Korea" ${d.country==="Korea"?"selected":""}>Южная Корея</option>
            <option value="China" ${d.country==="China"?"selected":""}>Китай</option>
          </select>
          <input name="make" value="${esc(d.make||"")}" placeholder="Марка">
          <input name="model" value="${esc(d.model||"")}" placeholder="Модель">
          <input name="year" type="number" value="${esc(d.year||"")}" placeholder="Год">
          <input name="vin" value="${esc(d.vin||"")}" placeholder="VIN / кузов">
          <input name="mileage" type="number" value="${esc(d.mileage||"")}" placeholder="Пробег">
          <input name="purchase_date" type="date" value="${esc(d.purchase_date||"")}">
          <input name="expected_price" type="number" value="${esc(d.expected_price||0)}" placeholder="Стоимость при покупке">
          <h2 style="margin-top:12px">Логистика</h2>
          <input name="current_location" value="${esc(d.current_location||"")}" placeholder="Текущая локация">
          <input name="departure_place" value="${esc(d.departure_place||"")}" placeholder="Порт / город отправления">
          <input name="tracking_url" value="${esc(d.tracking_url||"")}" placeholder="Ссылка отслеживания">
          <input name="departure_date" type="date" value="${esc(d.departure_date||"")}">
          <input name="eta" type="date" value="${esc(d.eta||"")}">
          <input name="arrival_place" value="${esc(d.arrival_place||"")}" placeholder="Порт / город прибытия">
          <input name="transport_company" value="${esc(d.transport_company||"")}" placeholder="Транспортная компания">
          <input name="waybill" value="${esc(d.waybill||"")}" placeholder="Номер накладной">
      </section>
      <section class="card">
          <h2>Финансы</h2>
          <input name="car_price" type="number" value="${esc(d.car_price||0)}" placeholder="Цена автомобиля">
          <input name="country_costs" type="number" value="${esc(d.country_costs||0)}" placeholder="Расходы по стране">
          <input name="delivery" type="number" value="${esc(d.delivery||0)}" placeholder="Доставка до России">
          <input name="customs_duty" type="number" value="${esc(d.customs_duty||0)}" placeholder="Таможенная пошлина">
          <input name="customs_clearance" type="number" value="${esc(d.customs_clearance||0)}" placeholder="Таможенное оформление">
          <input name="commission" type="number" value="${esc(d.commission||0)}" placeholder="Комиссия JPCars">
          <h2 style="margin-top:12px">Внутренняя заметка</h2>
          <input name="manager_note" value="${esc(d.manager_note||"")}" placeholder="Клиент не видит эту заметку">
          <button class="btn">Сохранить карточку</button>
        </form>
      </section>
    </div>
  </main>`,true));
});

app.post("/admin/edit/:id",admin,(req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE id=?").get(req.params.id);
  if(!d) return res.sendStatus(404);
  db.prepare(`UPDATE deals SET
    client_name=?,client_phone=?,country=?,make=?,model=?,year=?,vin=?,mileage=?,purchase_date=?,expected_price=?,
    current_location=?,departure_place=?,tracking_url=?,departure_date=?,eta=?,arrival_place=?,transport_company=?,waybill=?,
    car_price=?,country_costs=?,delivery=?,customs_duty=?,customs_clearance=?,commission=?,manager_note=?
    WHERE id=?`).run(
      req.body.client_name,req.body.client_phone,req.body.country,req.body.make,req.body.model,req.body.year||null,req.body.vin,
      req.body.mileage||null,req.body.purchase_date||"",Number(req.body.expected_price)||0,
      req.body.current_location,req.body.departure_place,req.body.tracking_url,req.body.departure_date,req.body.eta,req.body.arrival_place,
      req.body.transport_company,req.body.waybill,
      Number(req.body.car_price)||0,Number(req.body.country_costs)||0,Number(req.body.delivery)||0,Number(req.body.customs_duty)||0,
      Number(req.body.customs_clearance)||0,Number(req.body.commission)||0,req.body.manager_note||"",d.id
    );
  db.prepare("INSERT INTO events(deal_id,title,note) VALUES(?,?,?)").run(d.id,"Карточка сделки обновлена",`Данные изменил ${actorName(req)}.`);
  audit(req,{dealId:d.id,type:"deal",resourceId:d.id,action:"edit_card"});
  res.redirect("/admin/deal/"+d.id);
});

function registerDocRoute(prefix,isAdmin){
  app.post(prefix+"/:id",isAdmin?admin:(req,res,next)=>next(),upload.single("document"),(req,res)=>{
    const d=db.prepare("SELECT * FROM deals WHERE id=?").get(req.params.id);
    if(!d || !req.file) return res.sendStatus(400);
    db.prepare("INSERT INTO documents(deal_id,category,original_name,stored_name,uploader) VALUES(?,?,?,?,?)")
      .run(d.id,req.body.category,decodeUploadName(req.file.originalname),req.file.filename,isAdmin?"manager":"client");
    res.redirect(isAdmin?"/admin/deal/"+d.id:"/c/"+d.token);
  });
}
registerDocRoute("/admin/doc",true);

app.post("/c/:token/doc",publicLimiter,upload.single("document"),async (req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE token=? AND access_enabled=1").get(req.params.token);
  if(!d || !req.file) return res.sendStatus(403);
  db.prepare("INSERT INTO documents(deal_id,category,original_name,stored_name,uploader,status) VALUES(?,?,?,?,?,?)")
    .run(d.id,req.body.category,decodeUploadName(req.file.originalname),req.file.filename,"client","uploaded");
  const latestDoc=db.prepare("SELECT title FROM documents WHERE deal_id=? ORDER BY id DESC LIMIT 1").get(d.id);
  await notifyStaffClientUpload(d,latestDoc?.title||"Новый документ");
  res.redirect("/c/"+d.token);
});

app.post("/admin/media/:id",admin,upload.array("media",20),(req,res)=>{
  for(const f of req.files||[]){
    db.prepare("INSERT INTO media(deal_id,kind,caption,original_name,stored_name) VALUES(?,?,?,?,?)")
      .run(req.params.id,f.mimetype.startsWith("image/")?"image":"video",req.body.caption||"",decodeUploadName(f.originalname),f.filename);
  }
  res.redirect("/admin/deal/"+req.params.id);
});

app.get("/c/:token/doc/:id",(req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE token=? AND access_enabled=1").get(req.params.token);
  if(!d) return res.sendStatus(403);
  const x=db.prepare("SELECT * FROM documents WHERE id=? AND deal_id=?").get(req.params.id,d.id);
  if(!x) return res.sendStatus(404);
  const filePath=path.join(UPLOAD_DIR,x.stored_name);
  if(!fs.existsSync(filePath)) return res.sendStatus(404);
  audit(req,{dealId:d.id,type:"document",resourceId:x.id,actor:"client",action:"download"});
  res.download(filePath,x.original_name);
});

app.get("/admin/doc-file/:id",admin,(req,res)=>{
  const x=db.prepare("SELECT * FROM documents WHERE id=?").get(req.params.id);
  if(!x) return res.sendStatus(404);
  const filePath=path.join(UPLOAD_DIR,x.stored_name);
  if(!fs.existsSync(filePath)) return res.sendStatus(404);
  audit(req,{dealId:x.deal_id,type:"document",resourceId:x.id,actor:actorName(req),action:"download"});
  res.download(filePath,x.original_name);
});

app.get("/c/:token/media/:id",(req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE token=? AND access_enabled=1").get(req.params.token);
  if(!d) return res.sendStatus(403);
  const x=db.prepare("SELECT * FROM media WHERE id=? AND deal_id=?").get(req.params.id,d.id);
  if(!x) return res.sendStatus(404);
  const filePath=path.join(UPLOAD_DIR,x.stored_name);
  if(!fs.existsSync(filePath)) return res.sendStatus(404);
  audit(req,{dealId:d.id,type:"media",resourceId:x.id,actor:"client",action:"view"});
  res.sendFile(filePath);
});

app.get("/admin/media-file/:id",admin,(req,res)=>{
  const x=db.prepare("SELECT * FROM media WHERE id=?").get(req.params.id);
  if(!x) return res.sendStatus(404);
  const filePath=path.join(UPLOAD_DIR,x.stored_name);
  if(!fs.existsSync(filePath)) return res.sendStatus(404);
  audit(req,{dealId:x.deal_id,type:"media",resourceId:x.id,actor:actorName(req),action:"view"});
  res.sendFile(filePath);
});


app.post("/admin/doc/:docId/status",admin,(req,res)=>{
  const doc=db.prepare("SELECT * FROM documents WHERE id=?").get(req.params.docId);
  if(!doc) return res.sendStatus(404);
  const allowed=["uploaded","verified","replace"];
  const status=allowed.includes(req.body.status)?req.body.status:"uploaded";
  audit(req,{dealId:doc.deal_id,type:"document",resourceId:doc.id,action:`review:${status}`});
  db.prepare("UPDATE documents SET status=?,verified=?,manager_comment=? WHERE id=?")
    .run(status,status==="verified"?1:0,req.body.manager_comment||"",doc.id);
  res.redirect("/admin/deal/"+doc.deal_id);
});

app.post("/admin/doc/:docId/delete",admin,(req,res)=>{
  const doc=db.prepare("SELECT * FROM documents WHERE id=?").get(req.params.docId);
  if(!doc) return res.sendStatus(404);
  const p=path.join(UPLOAD_DIR,doc.stored_name);
  if(fs.existsSync(p)) fs.unlinkSync(p);
  db.prepare("DELETE FROM documents WHERE id=?").run(doc.id);
  res.redirect("/admin/deal/"+doc.deal_id);
});

app.post("/admin/media/:mediaId/delete",admin,(req,res)=>{
  const m=db.prepare("SELECT * FROM media WHERE id=?").get(req.params.mediaId);
  if(!m) return res.sendStatus(404);
  const p=path.join(UPLOAD_DIR,m.stored_name);
  if(fs.existsSync(p)) fs.unlinkSync(p);
  db.prepare("DELETE FROM media WHERE id=?").run(m.id);
  res.redirect("/admin/deal/"+m.deal_id);
});


app.post("/admin/access/:id/toggle",admin,(req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE id=?").get(req.params.id);
  if(!d) return res.sendStatus(404);
  db.prepare("UPDATE deals SET access_enabled=? WHERE id=?").run(d.access_enabled===0?1:0,d.id);
  res.redirect("/admin/deal/"+d.id);
});

app.post("/admin/access/:id/regenerate",admin,(req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE id=?").get(req.params.id);
  if(!d) return res.sendStatus(404);
  const token=crypto.randomBytes(24).toString("base64url");
  db.prepare("UPDATE deals SET token=?,access_enabled=1 WHERE id=?").run(token,d.id);
  db.prepare("INSERT INTO events(deal_id,title,note) VALUES(?,?,?)").run(d.id,"Обновлена ссылка клиента","Старая персональная ссылка отключена, создана новая.");
  res.redirect("/admin/deal/"+d.id);
});


app.post("/admin/archive/:id/toggle",admin,(req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE id=?").get(req.params.id);
  if(!d) return res.sendStatus(404);
  db.prepare("UPDATE deals SET archived=? WHERE id=?").run(d.archived?0:1,d.id);
  audit(req,{dealId:d.id,type:"deal",resourceId:d.id,action:d.archived?"restore":"archive"});
  res.redirect(d.archived?"/admin":"/admin?archive=1");
});

app.post("/admin/payment/:dealId/new",admin,upload.single("document"),(req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE id=?").get(req.params.dealId);
  if(!d) return res.sendStatus(404);
  const file=req.file;
  db.prepare(`INSERT INTO payments(deal_id,title,amount,status,note,document_name,document_stored)
    VALUES(?,?,?,?,?,?,?)`).run(
      d.id,req.body.title,Number(req.body.amount)||0,
      ["expected","issued","paid"].includes(req.body.status)?req.body.status:"expected",
      req.body.note||"",
      file?decodeUploadName(file.originalname):"",
      file?file.filename:""
    );
  res.redirect("/admin/deal/"+d.id);
});

app.get("/admin/payment-file/:id",admin,(req,res)=>{
  const p=db.prepare("SELECT * FROM payments WHERE id=?").get(req.params.id);
  if(!p||!p.document_stored) return res.sendStatus(404);
  const filePath=path.join(UPLOAD_DIR,p.document_stored);
  if(!fs.existsSync(filePath)) return res.sendStatus(404);
  audit(req,{dealId:p.deal_id,type:"payment",resourceId:p.id,actor:actorName(req),action:"download"});
  res.download(filePath,p.document_name||"payment-document");
});

app.get("/c/:token/payment/:id",(req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE token=? AND access_enabled=1").get(req.params.token);
  if(!d) return res.sendStatus(403);
  const p=db.prepare("SELECT * FROM payments WHERE id=? AND deal_id=?").get(req.params.id,d.id);
  if(!p||!p.document_stored) return res.sendStatus(404);
  const filePath=path.join(UPLOAD_DIR,p.document_stored);
  if(!fs.existsSync(filePath)) return res.sendStatus(404);
  audit(req,{dealId:d.id,type:"payment",resourceId:p.id,actor:"client",action:"download"});
  res.download(filePath,p.document_name||"payment-document");
});


app.get("/admin/team",superAdmin,(req,res)=>{
  const users=db.prepare("SELECT id,name,login,role,active,telegram_chat_id,telegram_username,telegram_first_name,notify_client_uploads,created_at FROM staff_users ORDER BY id").all();
  res.send(shell("Команда",`<main class="wrap">
    <div class="adminbar"><div><h1>Команда JPCars</h1><div class="muted">Менеджеры и доступ к админке</div></div><a href="/admin">← Сделки</a></div>
    <div class="grid">
      <section class="card">
        <h2>Сотрудники</h2>
        ${users.map(u=>`<div class="row">
          <div><b>${esc(u.name)}</b><div class="muted" style="font-size:12px;margin-top:3px">${esc(u.login)} · ${u.role==="admin"?"Администратор":"Менеджер"}${u.telegram_chat_id?`<div class="muted" style="font-size:12px;margin-top:3px">Telegram: подключён${u.telegram_username?` · @${esc(u.telegram_username)}`:""}</div>`:`<div style="margin-top:6px"><a class="btn light" target="_blank" href="${staffTelegramConnectUrl(u)}">Подключить Telegram</a></div>`}
            ${u.telegram_chat_id?`<form method="post" action="/admin/team/${u.id}/notify-toggle" style="margin-top:6px"><button class="btn light">${Number(u.notify_client_uploads)===1?"Не уведомлять о документах":"Уведомлять о документах"}</button></form>`:""}</div></div>
          <div style="text-align:right">
            <span class="doc-status ${u.active?"doc-ok":"doc-wait"}">${u.active?"Активен":"Отключён"}</span>
            ${u.id!==req.staff.id?`<form method="post" action="/admin/team/${u.id}/toggle" style="margin-top:6px"><button class="btn light">${u.active?"Отключить":"Включить"}</button></form>`:""}
          </div>
        </div>`).join("")}
      </section>
      <section class="card">
        <h2>Добавить сотрудника</h2>
        <form class="form" method="post" action="/admin/team/new">
          <input name="name" placeholder="Имя сотрудника" required>
          <input name="login" placeholder="Логин" required>
          <input name="password" type="password" placeholder="Пароль минимум 10 символов" required minlength="10">
          <select name="role"><option value="manager">Менеджер</option><option value="admin">Администратор</option></select>
          <button class="btn">Создать аккаунт</button>
        </form>
      </section>
    </div>
  </main>`,true));
});

app.post("/admin/team/new",superAdmin,(req,res)=>{
  const name=String(req.body.name||"").trim();
  const login=String(req.body.login||"").trim();
  const password=String(req.body.password||"");
  const role=req.body.role==="admin"?"admin":"manager";
  if(!name || !login || password.length<10) return res.status(400).send("Проверьте данные сотрудника.");
  if(db.prepare("SELECT id FROM staff_users WHERE login=?").get(login)) return res.status(400).send("Такой логин уже существует.");
  const p=hashPassword(password);
  const r=db.prepare("INSERT INTO staff_users(name,login,password_hash,password_salt,role,active) VALUES(?,?,?,?,?,1)")
    .run(name,login,p.hash,p.salt,role);
  audit(req,{type:"staff",resourceId:Number(r.lastInsertRowid),action:`create:${login}`});
  res.redirect("/admin/team");
});

app.post("/admin/team/:id/toggle",superAdmin,(req,res)=>{
  const u=db.prepare("SELECT * FROM staff_users WHERE id=?").get(req.params.id);
  if(!u || u.id===req.staff.id) return res.sendStatus(400);
  db.prepare("UPDATE staff_users SET active=? WHERE id=?").run(u.active?0:1,u.id);
  audit(req,{type:"staff",resourceId:u.id,action:`${u.active?"disable":"enable"}:${u.login}`});
  res.redirect("/admin/team");
});

app.get("/admin/broker/:id",admin,(req,res)=>{
  const d=db.prepare("SELECT * FROM deals WHERE id=?").get(req.params.id);
  if(!d) return res.sendStatus(404);
  const docs=db.prepare("SELECT * FROM documents WHERE deal_id=?").all(req.params.id);
  const archive=archiver("zip");
  res.attachment(`JPCars_${d.id}_broker.zip`);
  archive.pipe(res);
  for(const x of docs){
    const filePath=path.join(UPLOAD_DIR,x.stored_name);
    if(fs.existsSync(filePath)) archive.file(filePath,{name:x.category+"_"+x.original_name});
  }
  archive.finalize();
});


app.use((err,req,res,next)=>{
  console.error(err);
  const message=err && err.message ? err.message : "Ошибка сервера";
  res.status(400).send(shell("Ошибка",`<main class="wrap"><div class="card"><h1>Не удалось выполнить действие</h1><p class="muted">${esc(message)}</p><a class="btn" href="${currentStaff(req)?"/admin":"/"}">Вернуться</a></div></main>`,!!currentStaff(req)));
});

app.listen(PORT,"0.0.0.0",()=>console.log(`JPCars v1.2 listening on port ${PORT}; data=${DATA_ROOT}`));
