import type { Config, Context } from "@netlify/functions";
import { getStore } from "@netlify/blobs";
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

const notesStore = () => getStore({ name: "scout-notes", consistency: "strong" });
const usersStore = () => getStore({ name: "scout-users", consistency: "strong" });
const configStore = () => getStore({ name: "scout-config", consistency: "strong" });

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

const clip = (v: unknown, n: number) => String(v ?? "").slice(0, n);
const ID_RE = /^[a-z0-9]{6,40}$/;
const USER_RE = /^[a-z0-9_]{3,20}$/;
const TOKEN_DAYS = 180;

// Signing secret is created once and kept in Blobs, so no extra setup is needed.
async function secret(): Promise<string> {
  const s = configStore();
  const existing = await s.get("signing-secret");
  if (existing) return existing;
  await s.set("signing-secret", randomBytes(32).toString("hex"), { onlyIfNew: true });
  return (await s.get("signing-secret")) as string;
}

const sign = (data: string, key: string) => createHmac("sha256", key).update(data).digest("base64url");

async function makeToken(user: string) {
  const exp = Date.now() + TOKEN_DAYS * 864e5;
  const data = `${user}.${exp}`;
  return `${data}.${sign(data, await secret())}`;
}

async function readToken(req: Request): Promise<string | null> {
  const h = req.headers.get("authorization") ?? "";
  const tok = h.startsWith("Bearer ") ? h.slice(7) : "";
  const parts = tok.split(".");
  if (parts.length !== 3) return null;
  const [user, exp, sig] = parts;
  if (!USER_RE.test(user) || !(Number(exp) > Date.now())) return null;
  const good = sign(`${user}.${exp}`, await secret());
  const a = Buffer.from(sig), b = Buffer.from(good);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  const exists = await usersStore().get(user);
  return exists ? user : null;
}

const hashPw = (pw: string, salt: string) => scryptSync(pw, salt, 32).toString("hex");

async function signup(req: Request) {
  const body = await req.json().catch(() => ({}));
  const code = Netlify.env.get("TEAM_CODE");
  if (!code || clip(body.code, 100).trim() !== code) return json({ error: "Wrong team code" }, 401);
  const name = clip(body.username, 20).trim();
  const user = name.toLowerCase();
  const pw = clip(body.password, 200);
  if (!USER_RE.test(user)) return json({ error: "Username: 3–20 letters, numbers or _" }, 400);
  if (pw.length < 6) return json({ error: "Password needs at least 6 characters" }, 400);
  const salt = randomBytes(16).toString("hex");
  const { modified } = await usersStore().setJSON(
    user,
    { name, salt, hash: hashPw(pw, salt), created: new Date().toISOString() },
    { onlyIfNew: true },
  );
  if (!modified) return json({ error: "That username is taken" }, 409);
  return json({ token: await makeToken(user), user, name });
}

async function login(req: Request) {
  const body = await req.json().catch(() => ({}));
  const user = clip(body.username, 20).trim().toLowerCase();
  const pw = clip(body.password, 200);
  const rec: any = USER_RE.test(user) ? await usersStore().get(user, { type: "json" }) : null;
  if (!rec) return json({ error: "Wrong username or password" }, 401);
  const a = Buffer.from(hashPw(pw, rec.salt), "hex"), b = Buffer.from(rec.hash, "hex");
  if (a.length !== b.length || !timingSafeEqual(a, b)) return json({ error: "Wrong username or password" }, 401);
  return json({ token: await makeToken(user), user, name: rec.name || user });
}

async function listNotes() {
  const s = notesStore();
  const { blobs } = await s.list();
  const notes = await Promise.all(
    blobs.map(async (b) => {
      const v = await s.get(b.key, { type: "json" });
      return v ? { id: b.key, ...v } : null;
    }),
  );
  return json({ notes: notes.filter(Boolean) });
}

async function addNotes(req: Request, user: string) {
  const body = await req.json().catch(() => null);
  const list = Array.isArray(body?.notes) ? body.notes.slice(0, 12) : [];
  if (!list.length) return json({ error: "Nothing to save" }, 400);
  const rec: any = await usersStore().get(user, { type: "json" });
  const s = notesStore();
  const saved = [];
  for (const n of list) {
    const id = clip(n.id, 40).toLowerCase();
    const team = clip(n.team, 6).replace(/\D/g, "");
    if (!ID_RE.test(id) || !team) continue;
    const note = {
      team,
      match: clip(n.match, 10),
      author: user,
      scout: rec?.name || user,
      tags: Array.isArray(n.tags) ? n.tags.slice(0, 12).map((t: unknown) => clip(t, 40)) : [],
      text: clip(n.text, 2000),
      at: new Date().toISOString(),
    };
    await s.setJSON(id, note, { onlyIfNew: true });
    saved.push(id);
  }
  return json({ saved }, 201);
}

async function deleteNote(req: Request, user: string) {
  const id = new URL(req.url).searchParams.get("id") ?? "";
  if (!ID_RE.test(id)) return json({ error: "Bad id" }, 400);
  const s = notesStore();
  const note: any = await s.get(id, { type: "json" });
  if (!note) return json({ ok: true });
  if (note.author && note.author !== user) return json({ error: "You can only delete your own notes" }, 403);
  await s.delete(id);
  return json({ ok: true });
}

export default async (req: Request, context: Context) => {
  const path = new URL(req.url).pathname;
  try {
    if (path === "/api/signup" && req.method === "POST") return await signup(req);
    if (path === "/api/login" && req.method === "POST") return await login(req);

    const user = await readToken(req);
    if (!user) return json({ error: "Please sign in" }, 401);
    if (path === "/api/me") return json({ user });
    if (path === "/api/notes") {
      if (req.method === "GET") return await listNotes();
      if (req.method === "POST") return await addNotes(req, user);
      if (req.method === "DELETE") return await deleteNote(req, user);
    }
    return json({ error: "Not found" }, 404);
  } catch (e) {
    console.error(e);
    return json({ error: "Server error" }, 500);
  }
};

export const config: Config = {
  path: ["/api/notes", "/api/signup", "/api/login", "/api/me"],
  method: ["GET", "POST", "DELETE"],
};
