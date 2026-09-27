import express from "express";
import cors from "cors";
import crypto from "crypto";
import pg from "pg";
const { Pool } = pg;
const app = express();
app.use(cors({ origin: true }));
app.use(express.json({ limit: "1mb" }));
const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const TEACHER_PASSWORD = process.env.TEACHER_PASSWORD;
const API_SECRET = process.env.API_SECRET;
if (!DATABASE_URL || !TEACHER_PASSWORD || !API_SECRET) { console.error("Missing required env vars"); process.exit(1); }
const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
const b64 = b => Buffer.from(b).toString("base64url");
const hash = v => crypto.createHash("sha256").update(String(v)).digest("hex");
const randomToken = () => crypto.randomBytes(32).toString("hex");
function sign(payload) {
  const body = b64(JSON.stringify(payload));
  const sig = b64(crypto.createHmac("sha256", API_SECRET).update(body).digest());
  return body + "." + sig;
}
function verify(token) {
  try {
    const [body, sig] = String(token || "").split(".");
    if (!body || !sig) return null;
    const expected = b64(crypto.createHmac("sha256", API_SECRET).update(body).digest());
    if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p.exp && p.exp > Date.now() ? p : null;
  } catch { return null; }
}
async function init() {
  await pool.query(`CREATE TABLE IF NOT EXISTS students (
    id BIGSERIAL PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
    class_name TEXT DEFAULT '', progress JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
}
function teacher(req,res,next) {
  const p=verify(req.headers.authorization?.replace(/^Bearer\\s+/i,""));
  if(!p || p.role!=="teacher") return res.status(401).json({error:"غير مصرح"});
  next();
}
function student(req,res,next) {
  const p=verify(req.headers.authorization?.replace(/^Bearer\\s+/i,""));
  if(!p || p.role!=="student" || !p.tokenHash) return res.status(401).json({error:"جلسة الطالبة غير صالحة"});
  req.tokenHash=p.tokenHash; next();
}
app.get("/health", async (_req,res)=>{ try{await pool.query("SELECT 1");res.json({ok:true});}catch{res.status(503).json({ok:false});} });
app.post("/api/teacher/login",(req,res)=>{
  const a=Buffer.from(String(req.body?.password||"")),b=Buffer.from(TEACHER_PASSWORD);
  if(a.length!==b.length || !crypto.timingSafeEqual(a,b)) return res.status(401).json({error:"كلمة المرور غير صحيحة"});
  res.json({token:sign({role:"teacher",exp:Date.now()+12*60*60*1000})});
});
app.post("/api/student/register",async(req,res)=>{
  const name=String(req.body?.name||"").trim(), className=String(req.body?.className||"").trim();
  if(name.length<2) return res.status(400).json({error:"اسم الطالبة مطلوب"});
  const raw=randomToken(), tokenHash=hash(raw);
  const r=await pool.query("INSERT INTO students(token_hash,name,class_name) VALUES($1,$2,$3) RETURNING id,name,class_name",[tokenHash,name,className]);
  res.json({token:sign({role:"student",tokenHash,exp:Date.now()+365*24*60*60*1000}),student:{id:r.rows[0].id,name:r.rows[0].name,className:r.rows[0].class_name}});
});
app.put("/api/student/progress",student,async(req,res)=>{
  const progress=req.body?.progress;
  if(!progress || typeof progress!=="object") return res.status(400).json({error:"بيانات التقدم غير صالحة"});
  await pool.query("UPDATE students SET progress=$1::jsonb,last_seen=NOW() WHERE token_hash=$2",[JSON.stringify(progress),req.tokenHash]);
  res.json({ok:true});
});
app.get("/api/student/me",student,async(req,res)=>{
  const r=await pool.query("SELECT id,name,class_name,progress,last_seen FROM students WHERE token_hash=$1",[req.tokenHash]);
  if(!r.rowCount) return res.status(404).json({error:"الطالبة غير موجودة"});
  res.json({student:r.rows[0]});
});
app.get("/api/teacher/students",teacher,async(_req,res)=>{
  const r=await pool.query("SELECT id,name,class_name,progress,last_seen,created_at FROM students ORDER BY name ASC");
  res.json({students:r.rows});
});
init().then(()=>app.listen(PORT,()=>console.log(`Teacher Huda API listening on ${PORT}`))).catch(e=>{console.error(e);process.exit(1);});
