const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const multer = require("multer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const SQLiteStoreFactory = require("connect-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "CHANGE-ME-before-public-deployment-" + crypto.randomBytes(24).toString("hex");
const ROOT = __dirname;
const UPLOAD_DIR = path.join(ROOT, "uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(path.join(ROOT, "isit.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 handle TEXT NOT NULL UNIQUE,
 phone TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 avatar TEXT DEFAULT '',
 bio TEXT DEFAULT '',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS posts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 caption TEXT DEFAULT '',
 media_path TEXT NOT NULL,
 media_type TEXT NOT NULL,
 visibility TEXT NOT NULL DEFAULT 'public',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS reactions (
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK(kind IN ('like','dislike')),
 PRIMARY KEY(user_id, post_id)
);
CREATE TABLE IF NOT EXISTS comments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
 body TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS follows (
 follower_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 followed_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(follower_id, followed_id),
 CHECK(follower_id <> followed_id)
);
CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id, created_at);
`);

const SQLiteStore = SQLiteStoreFactory(session);
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
 store: new SQLiteStore({ db: "sessions.sqlite", dir: ROOT }),
 secret: SESSION_SECRET,
 resave: false,
 saveUninitialized: false,
 cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 1000 * 60 * 60 * 24 * 7 }
}));
app.use("/uploads", express.static(UPLOAD_DIR, { fallthrough: false, maxAge: "1h" }));
app.use(express.static(path.join(ROOT, "public")));
app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false }));

const upload = multer({
 storage: multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
   const ext = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g, "");
   cb(null, crypto.randomUUID() + ext);
  }
 }),
 limits: { fileSize: 100 * 1024 * 1024 },
 fileFilter: (_req, file, cb) => {
  const ok = /^(image\/(jpeg|png|gif|webp)|video\/(mp4|webm|quicktime))$/.test(file.mimetype);
  cb(ok ? null : new Error("Format non accepté. Utilise JPG, PNG, GIF, WEBP, MP4, WEBM ou MOV."), ok);
 }
});

function safeUser(row) {
 if (!row) return null;
 return { id: row.id, name: row.name, handle: row.handle, phone: row.phone, avatar: row.avatar || "", bio: row.bio || "" };
}
function auth(req, res, next) {
 if (!req.session.userId) return res.status(401).json({ error: "Connecte-toi pour continuer." });
 const user = db.prepare("SELECT * FROM users WHERE id=?").get(req.session.userId);
 if (!user) { req.session.destroy(() => {}); return res.status(401).json({ error: "Session expirée." }); }
 req.user = user; next();
}
function postShape(row, viewerId) {
 const counts = db.prepare("SELECT kind, COUNT(*) n FROM reactions WHERE post_id=? GROUP BY kind").all(row.id);
 const likes = counts.find(x => x.kind === "like")?.n || 0;
 const dislikes = counts.find(x => x.kind === "dislike")?.n || 0;
 const mine = viewerId ? db.prepare("SELECT kind FROM reactions WHERE post_id=? AND user_id=?").get(row.id, viewerId)?.kind || null : null;
 const comments = db.prepare(`SELECT c.id,c.body,c.created_at,u.name,u.handle,u.avatar FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.id`).all(row.id);
 const followers = db.prepare("SELECT COUNT(*) n FROM follows WHERE followed_id=?").get(row.user_id).n;
 return { id: row.id, caption: row.caption, mediaUrl: row.media_path, mediaType: row.media_type, visibility: row.visibility,
  createdAt: row.created_at, author: { id: row.user_id, name: row.name, handle: row.handle, avatar: row.avatar || "", followers },
  likes, dislikes, myReaction: mine, comments };
}
app.get("/api/health", (_req,res)=>res.json({ok:true,app:"ISIT",version:"1.0.0"}));
app.post("/api/auth/register", async (req,res,next)=>{
 try {
  const {name,phone,password} = req.body;
  if (!name || !phone || !password) return res.status(400).json({error:"Nom, téléphone et mot de passe sont obligatoires."});
  if (String(password).length < 8) return res.status(400).json({error:"Le mot de passe doit contenir au moins 8 caractères."});
  const cleanPhone = String(phone).replace(/[^\d+]/g,"");
  if (cleanPhone.length < 8 || cleanPhone.length > 18) return res.status(400).json({error:"Numéro de téléphone invalide."});
  const handle = String(name).normalize("NFD").replace(/[\u0300-\u036f]/g,"").toLowerCase().replace(/[^a-z0-9_]/g,"").slice(0,24) || "isituser";
  const uniqueHandle = handle + "_" + crypto.randomBytes(2).toString("hex");
  const hash = await bcrypt.hash(password, 12);
  const result = db.prepare("INSERT INTO users(name,handle,phone,password_hash) VALUES(?,?,?,?)").run(String(name).trim().slice(0,60), uniqueHandle, cleanPhone, hash);
  req.session.userId = result.lastInsertRowid;
  res.status(201).json({user:safeUser(db.prepare("SELECT * FROM users WHERE id=?").get(result.lastInsertRowid)),phoneVerified:false,
   notice:"Compte créé. Le numéro n'est pas encore vérifié par SMS."});
 } catch(e) { if (String(e.message).includes("UNIQUE")) return res.status(409).json({error:"Ce numéro est déjà associé à un compte."}); next(e); }
});
app.post("/api/auth/login", async (req,res,next)=>{
 try {
  const {phone,password}=req.body;
  const row=db.prepare("SELECT * FROM users WHERE phone=?").get(String(phone||"").replace(/[^\d+]/g,""));
  if (!row || !await bcrypt.compare(String(password||""),row.password_hash)) return res.status(401).json({error:"Numéro ou mot de passe incorrect."});
  req.session.userId=row.id; res.json({user:safeUser(row)});
 } catch(e){next(e);}
});
app.post("/api/auth/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>{if(!req.session.userId)return res.json({user:null});res.json({user:safeUser(db.prepare("SELECT * FROM users WHERE id=?").get(req.session.userId))});});
app.patch("/api/me",auth,upload.single("avatar"),(req,res)=>{
 const name=String(req.body.name||req.user.name).trim().slice(0,60);
 const bio=String(req.body.bio||"").slice(0,160);
 const avatar=req.file?"/uploads/"+req.file.filename:req.user.avatar;
 db.prepare("UPDATE users SET name=?,bio=?,avatar=? WHERE id=?").run(name,bio,avatar,req.user.id);
 res.json({user:safeUser(db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id))});
});
app.get("/api/posts",(req,res)=>{
 const mode=req.query.mode==="following"?"following":"public";
 let rows;
 if(mode==="following" && req.session.userId){
  rows=db.prepare(`SELECT p.*,u.name,u.handle,u.avatar FROM posts p JOIN users u ON u.id=p.user_id
   WHERE p.visibility IN ('public','followers') AND (p.user_id=? OR p.user_id IN (SELECT followed_id FROM follows WHERE follower_id=?))
   ORDER BY p.id DESC LIMIT 100`).all(req.session.userId,req.session.userId);
 } else {
  rows=db.prepare(`SELECT p.*,u.name,u.handle,u.avatar FROM posts p JOIN users u ON u.id=p.user_id
   WHERE p.visibility='public' ORDER BY p.id DESC LIMIT 100`).all();
 }
 res.json({posts:rows.map(r=>postShape(r,req.session.userId))});
});
app.post("/api/posts",auth,upload.single("media"),(req,res)=>{
 if(!req.file)return res.status(400).json({error:"Choisis une photo ou une vidéo."});
 const type=req.file.mimetype.startsWith("video/")?"video":"image";
 const caption=String(req.body.caption||"").slice(0,2200);
 const visibility=["public","followers","private"].includes(req.body.visibility)?req.body.visibility:"public";
 const result=db.prepare("INSERT INTO posts(user_id,caption,media_path,media_type,visibility) VALUES(?,?,?,?,?)").run(req.user.id,caption,"/uploads/"+req.file.filename,type,visibility);
 const row=db.prepare("SELECT p.*,u.name,u.handle,u.avatar FROM posts p JOIN users u ON u.id=p.user_id WHERE p.id=?").get(result.lastInsertRowid);
 res.status(201).json({post:postShape(row,req.user.id)});
});
app.post("/api/posts/:id/reaction",auth,(req,res)=>{
 const id=Number(req.params.id),kind=req.body.kind;
 if(!["like","dislike",null].includes(kind))return res.status(400).json({error:"Réaction invalide."});
 const exists=db.prepare("SELECT id FROM posts WHERE id=?").get(id);if(!exists)return res.status(404).json({error:"Publication introuvable."});
 if(kind===null)db.prepare("DELETE FROM reactions WHERE user_id=? AND post_id=?").run(req.user.id,id);
 else db.prepare("INSERT INTO reactions(user_id,post_id,kind) VALUES(?,?,?) ON CONFLICT(user_id,post_id) DO UPDATE SET kind=excluded.kind").run(req.user.id,id,kind);
 res.json({ok:true});
});
app.post("/api/posts/:id/comments",auth,(req,res)=>{
 const body=String(req.body.body||"").trim().slice(0,1000);if(!body)return res.status(400).json({error:"Écris un commentaire."});
 if(!db.prepare("SELECT id FROM posts WHERE id=?").get(Number(req.params.id)))return res.status(404).json({error:"Publication introuvable."});
 const r=db.prepare("INSERT INTO comments(user_id,post_id,body) VALUES(?,?,?)").run(req.user.id,Number(req.params.id),body);
 res.status(201).json({id:r.lastInsertRowid});
});
app.post("/api/users/:id/follow",auth,(req,res)=>{
 const id=Number(req.params.id);if(id===req.user.id)return res.status(400).json({error:"Tu ne peux pas t'abonner à ton propre compte."});
 if(!db.prepare("SELECT id FROM users WHERE id=?").get(id))return res.status(404).json({error:"Utilisateur introuvable."});
 const exists=db.prepare("SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?").get(req.user.id,id);
 if(exists)db.prepare("DELETE FROM follows WHERE follower_id=? AND followed_id=?").run(req.user.id,id);
 else db.prepare("INSERT INTO follows(follower_id,followed_id) VALUES(?,?)").run(req.user.id,id);
 res.json({following:!exists});
});
app.get("/api/search",(req,res)=>{
 const q="%"+String(req.query.q||"").slice(0,80)+"%";
 const users=db.prepare("SELECT id,name,handle,avatar FROM users WHERE name LIKE ? OR handle LIKE ? LIMIT 20").all(q,q);
 const posts=db.prepare("SELECT p.*,u.name,u.handle,u.avatar FROM posts p JOIN users u ON u.id=p.user_id WHERE p.visibility='public' AND p.caption LIKE ? ORDER BY p.id DESC LIMIT 30").all(q);
 res.json({users,posts:posts.map(r=>postShape(r,req.session.userId))});
});
app.get("/api/users/:handle",(req,res)=>{
 const u=db.prepare("SELECT id,name,handle,avatar,bio FROM users WHERE handle=?").get(req.params.handle);
 if(!u)return res.status(404).json({error:"Utilisateur introuvable."});
 const counts={posts:db.prepare("SELECT COUNT(*) n FROM posts WHERE user_id=? AND visibility='public'").get(u.id).n,
 followers:db.prepare("SELECT COUNT(*) n FROM follows WHERE followed_id=?").get(u.id).n,
 following:db.prepare("SELECT COUNT(*) n FROM follows WHERE follower_id=?").get(u.id).n};
 res.json({user:u,counts});
});
app.use((err,_req,res,_next)=>{
 console.error(err);
 const status=err instanceof multer.MulterError?400:500;
 res.status(status).json({error:status===500?"Erreur interne du serveur.":err.message});
});
app.listen(PORT,()=>console.log(`ISIT est lancé : http://localhost:${PORT}`));
