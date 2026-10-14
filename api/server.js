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

  // Merge old duplicate rows (same normalized student name + class) before enforcing uniqueness.
  await pool.query(`
    WITH ranked AS (
      SELECT id,
        lower(trim(name)) AS name_key,
        lower(trim(COALESCE(class_name, ''))) AS class_key,
        row_number() OVER (
          PARTITION BY lower(trim(name)), lower(trim(COALESCE(class_name, '')))
          ORDER BY
            COALESCE(NULLIF(progress->>'xp','')::numeric,0) DESC,
            COALESCE(NULLIF(progress->>'answered','')::numeric,0) DESC,
            last_seen DESC, id ASC
        ) AS rn
      FROM students
    ),
    winners AS (
      SELECT id, name_key, class_key FROM ranked WHERE rn = 1
    ),
    progress_items AS (
      SELECT r.name_key, r.class_key, kv.key, kv.value,
        row_number() OVER (
          PARTITION BY r.name_key, r.class_key, kv.key
          ORDER BY
            COALESCE(NULLIF(s.progress->>'xp','')::numeric,0) DESC,
            COALESCE(NULLIF(s.progress->>'answered','')::numeric,0) DESC,
            s.last_seen DESC, s.id ASC
        ) AS value_rank
      FROM students s
      JOIN ranked r ON r.id = s.id
      CROSS JOIN LATERAL jsonb_each(
        CASE WHEN jsonb_typeof(s.progress) = 'object' THEN s.progress ELSE '{}'::jsonb END
      ) AS kv
    ),
    merged AS (
      SELECT name_key, class_key, jsonb_object_agg(key, value) AS progress
      FROM progress_items
      WHERE value_rank = 1
      GROUP BY name_key, class_key
    ),
    updated AS (
      UPDATE students s
      SET progress = m.progress
      FROM merged m
      JOIN winners w USING (name_key, class_key)
      WHERE s.id = w.id
      RETURNING s.id
    )
    DELETE FROM students s
    USING ranked r
    WHERE s.id = r.id AND r.rn > 1
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS students_name_class_unique
    ON students (lower(trim(name)), lower(trim(COALESCE(class_name, ''))))
  `);

  // Keep multiple device tokens linked to the same student record.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS student_tokens (
      token_hash TEXT PRIMARY KEY,
      student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    INSERT INTO student_tokens(token_hash, student_id)
    SELECT token_hash, id FROM students
    ON CONFLICT (token_hash) DO NOTHING
  `);
}
function teacher(req,res,next) {
  const p=verify(req.headers.authorization?.replace(/^Bearer\s+/i,""));
  if(!p || p.role!=="teacher") return res.status(401).json({error:"غير مصرح"});
  next();
}
function student(req,res,next) {
  const p=verify(req.headers.authorization?.replace(/^Bearer\s+/i,""));
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
  const r=await pool.query(
    `INSERT INTO students(token_hash,name,class_name) VALUES($1,$2,$3)
     ON CONFLICT (lower(trim(name)), lower(trim(COALESCE(class_name, ''))))
     DO UPDATE SET token_hash=EXCLUDED.token_hash, name=EXCLUDED.name,
       class_name=EXCLUDED.class_name, last_seen=NOW()
     RETURNING id,name,class_name,progress`,
    [tokenHash,name,className]
  );
  await pool.query(
    "INSERT INTO student_tokens(token_hash,student_id) VALUES($1,$2) ON CONFLICT(token_hash) DO UPDATE SET student_id=EXCLUDED.student_id",
    [tokenHash,r.rows[0].id]
  );
  res.json({
    token:sign({role:"student",tokenHash,exp:Date.now()+365*24*60*60*1000}),
    student:{id:r.rows[0].id,name:r.rows[0].name,className:r.rows[0].class_name,progress:r.rows[0].progress}
  });
});
app.put("/api/student/progress",student,async(req,res)=>{
  const progress=req.body?.progress;
  if(!progress || typeof progress!=="object") return res.status(400).json({error:"بيانات التقدم غير صالحة"});
  const result=await pool.query(
    `UPDATE students s SET progress=$1::jsonb,last_seen=NOW()
     FROM student_tokens st
     WHERE st.token_hash=$2 AND st.student_id=s.id
       AND COALESCE(NULLIF(s.progress->>'xp','')::numeric,0) <= $3
       AND COALESCE(NULLIF(s.progress->>'answered','')::numeric,0) <= $4`,
    [JSON.stringify(progress),req.tokenHash,Number(progress.xp)||0,Number(progress.answered)||0]
  );
  if (!result.rowCount) {
    const tokenRow=await pool.query("SELECT 1 FROM student_tokens WHERE token_hash=$1",[req.tokenHash]);
    if (!tokenRow.rowCount) return res.status(401).json({error:"انتهت جلسة الطالبة"});
  }
  res.json({ok:result.rowCount>0,stale:result.rowCount===0});
});
app.get("/api/student/me",student,async(req,res)=>{
  const r=await pool.query("SELECT s.id,s.name,s.class_name,s.progress,s.last_seen FROM students s JOIN student_tokens st ON st.student_id=s.id WHERE st.token_hash=$1",[req.tokenHash]);
  if(!r.rowCount) return res.status(404).json({error:"الطالبة غير موجودة"});
  res.json({student:r.rows[0]});
});
app.get("/api/teacher/students",teacher,async(_req,res)=>{
  const r=await pool.query("SELECT id,name,class_name,progress,last_seen,created_at FROM students ORDER BY name ASC");
  res.json({students:r.rows});
});
init().then(()=>app.listen(PORT,()=>console.log(`Teacher Huda API listening on ${PORT}`))).catch(e=>{console.error(e);process.exit(1);});
