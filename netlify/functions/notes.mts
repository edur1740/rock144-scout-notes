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

type UserRec = {
  name: string;
  salt: string;
  hash: string;
  created: string;
  admin?: boolean;
  disabled?: boolean;
  tv?: number; // token version: bumping it signs the user out everywhere
  // Only for passwords set by the owner or an admin (never one a scout chose).
  // Shown to the owner so they can hand logins out.
  assigned?: string;
  createdBy?: string;
};

// Usernames listed in the ADMINS environment variable are always admins.
const envAdmins = () =>
  (Netlify.env.get("ADMINS") ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
// The owner is stored in the app so it can be handed to someone else.
// Until it's set, the first name in ADMINS is the owner.
async function getOwner(): Promise<string> {
  const v: any = await configStore().get("owner", { type: "json" });
  if (v?.user && (await usersStore().get(v.user))) return v.user;
  return envAdmins()[0] ?? "";
}
const isAdmin = (user: string, rec: UserRec | null, owner: string) =>
  !!rec && (rec.admin === true || envAdmins().includes(user) || user === owner);

async function signupsOpen() {
  const v: any = await configStore().get("settings", { type: "json" });
  return v?.signupsOpen !== false;
}

// Signing secret is created once and kept in Blobs, so no extra setup is needed.
async function secret(): Promise<string> {
  const s = configStore();
  const existing = await s.get("signing-secret");
  if (existing) return existing;
  await s.set("signing-secret", randomBytes(32).toString("hex"), { onlyIfNew: true });
  return (await s.get("signing-secret")) as string;
}

const sign = (data: string, key: string) => createHmac("sha256", key).update(data).digest("base64url");
const getUser = async (user: string) => (await usersStore().get(user, { type: "json" })) as UserRec | null;
const putUser = (user: string, rec: UserRec) => usersStore().setJSON(user, rec);

async function makeToken(user: string, tv: number) {
  const exp = Date.now() + TOKEN_DAYS * 864e5;
  const data = `${user}.${tv}.${exp}`;
  return `${data}.${sign(data, await secret())}`;
}

async function readToken(req: Request): Promise<{ user: string; rec: UserRec } | null> {
  const h = req.headers.get("authorization") ?? "";
  const parts = (h.startsWith("Bearer ") ? h.slice(7) : "").split(".");
  if (parts.length !== 4) return null;
  const [user, tv, exp, sig] = parts;
  if (!USER_RE.test(user) || !(Number(exp) > Date.now())) return null;
  const good = sign(`${user}.${tv}.${exp}`, await secret());
  const a = Buffer.from(sig), b = Buffer.from(good);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  const rec = await getUser(user);
  if (!rec || rec.disabled || String(rec.tv ?? 0) !== tv) return null;
  return { user, rec };
}

const hashPw = (pw: string, salt: string) => scryptSync(pw, salt, 32).toString("hex");
const setPw = (rec: UserRec, pw: string) => {
  rec.salt = randomBytes(16).toString("hex");
  rec.hash = hashPw(pw, rec.salt);
};

async function signup(req: Request) {
  const body = await req.json().catch(() => ({}));
  const code = Netlify.env.get("TEAM_CODE");
  if (!(await signupsOpen())) return json({ error: "Sign-up is closed. Ask your scouting lead for a login." }, 403);
  if (!code || clip(body.code, 100).trim() !== code) return json({ error: "Wrong team code" }, 401);
  const name = clip(body.username, 20).trim();
  const user = name.toLowerCase();
  const pw = clip(body.password, 200);
  if (!USER_RE.test(user)) return json({ error: "Username: 3–20 letters, numbers or _" }, 400);
  if (pw.length < 6) return json({ error: "Password needs at least 6 characters" }, 400);
  const rec: UserRec = { name, salt: "", hash: "", created: new Date().toISOString(), tv: 0 };
  setPw(rec, pw);
  const { modified } = await usersStore().setJSON(user, rec, { onlyIfNew: true });
  if (!modified) return json({ error: "That username is taken" }, 409);
  const owner = await getOwner();
  return json({ token: await makeToken(user, 0), user, name, admin: isAdmin(user, rec, owner), owner: user === owner });
}

async function login(req: Request) {
  const body = await req.json().catch(() => ({}));
  const user = clip(body.username, 20).trim().toLowerCase();
  const pw = clip(body.password, 200);
  const rec = USER_RE.test(user) ? await getUser(user) : null;
  if (!rec) return json({ error: "Wrong username or password" }, 401);
  const a = Buffer.from(hashPw(pw, rec.salt), "hex"), b = Buffer.from(rec.hash, "hex");
  if (a.length !== b.length || !timingSafeEqual(a, b)) return json({ error: "Wrong username or password" }, 401);
  if (rec.disabled) return json({ error: "This account is turned off. Ask an admin." }, 403);
  const owner = await getOwner();
  return json({ token: await makeToken(user, rec.tv ?? 0), user, name: rec.name || user, admin: isAdmin(user, rec, owner), owner: user === owner });
}

async function allNotes() {
  const s = notesStore();
  const { blobs } = await s.list();
  const notes = await Promise.all(
    blobs.map(async (b) => {
      const v = await s.get(b.key, { type: "json" });
      return v ? { id: b.key, ...(v as object) } : null;
    }),
  );
  return notes.filter(Boolean) as any[];
}

async function addNotes(req: Request, user: string, rec: UserRec) {
  const body = await req.json().catch(() => null);
  const list = Array.isArray(body?.notes) ? body.notes.slice(0, 12) : [];
  if (!list.length) return json({ error: "Nothing to save" }, 400);
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
      scout: rec.name || user,
      tags: Array.isArray(n.tags) ? n.tags.slice(0, 12).map((t: unknown) => clip(t, 40)) : [],
      text: clip(n.text, 2000),
      at: new Date().toISOString(),
    };
    await s.setJSON(id, note, { onlyIfNew: true });
    saved.push(id);
  }
  return json({ saved }, 201);
}

async function deleteNote(req: Request, user: string, admin: boolean) {
  const id = new URL(req.url).searchParams.get("id") ?? "";
  if (!ID_RE.test(id)) return json({ error: "Bad id" }, 400);
  const s = notesStore();
  const note: any = await s.get(id, { type: "json" });
  if (!note) return json({ ok: true });
  if (!admin && note.author && note.author !== user) return json({ error: "You can only delete your own notes" }, 403);
  await s.delete(id);
  return json({ ok: true });
}

/* ---------- admin ---------- */
async function listUsers(me: string) {
  const ownerName = await getOwner();
  const owner = me === ownerName;
  const s = usersStore();
  const { blobs } = await s.list();
  const notes = await allNotes();
  const counts: Record<string, number> = {};
  notes.forEach((n) => n.author && (counts[n.author] = (counts[n.author] || 0) + 1));
  const envA = envAdmins();
  const users = await Promise.all(
    blobs.map(async ({ key }) => {
      const r = (await s.get(key, { type: "json" })) as UserRec | null;
      if (!r) return null;
      return {
        user: key,
        name: r.name || key,
        created: r.created,
        admin: r.admin === true || envA.includes(key) || key === ownerName,
        isOwner: key === ownerName,
        lockedAdmin: envA.includes(key),
        disabled: !!r.disabled,
        assigned: !!r.assigned,
        password: owner && r.assigned ? r.assigned : null,
        notes: counts[key] || 0,
      };
    }),
  );
  return json({ users: users.filter(Boolean), owner, signupsOpen: await signupsOpen() });
}

async function adminAction(req: Request, me: string, owner: string) {
  const iAmOwner = me === owner;
  const body = await req.json().catch(() => ({}));
  const action = clip(body.action, 30);

  if (action === "signups") {
    const open = body.open === true;
    await configStore().setJSON("settings", { signupsOpen: open });
    return json({ ok: true, message: open ? "Scouts can sign up with the team code." : "Sign-up is closed. Only you and admins can make accounts." });
  }
  if (action === "create") {
    const name = clip(body.user, 20).trim();
    const user = name.toLowerCase();
    const pw = clip(body.password, 200);
    if (!USER_RE.test(user)) return json({ error: "Username: 3–20 letters, numbers or _" }, 400);
    if (pw.length < 6) return json({ error: "Password needs at least 6 characters" }, 400);
    const rec: UserRec = { name, salt: "", hash: "", created: new Date().toISOString(), tv: 0, assigned: pw, createdBy: me };
    setPw(rec, pw);
    const { modified } = await usersStore().setJSON(user, rec, { onlyIfNew: true });
    if (!modified) return json({ error: "That username is taken" }, 409);
    return json({ ok: true, message: `Created ${name}. Password: ${pw}` });
  }

  const target = clip(body.user, 20).toLowerCase();
  if (!USER_RE.test(target)) return json({ error: "Unknown account" }, 400);
  const rec = await getUser(target);
  if (!rec) return json({ error: "Unknown account" }, 404);
  const self = target === me;
  const locked = envAdmins().includes(target);
  const targetIsAdmin = isAdmin(target, rec, owner);
  // Owner manages everyone but themself; admins manage regular scouts only.
  const canManage = iAmOwner ? !self : !targetIsAdmin && target !== owner;

  if (action === "transfer") {
    if (!iAmOwner) return json({ error: "Only the owner can give away ownership" }, 403);
    if (self) return json({ error: "You're already the owner" }, 400);
    if (rec.disabled) return json({ error: "Turn this account back on first" }, 400);
    rec.admin = true;
    await putUser(target, rec);
    const mine = await getUser(me);
    if (mine) { mine.admin = true; await putUser(me, mine); }
    await configStore().setJSON("owner", { user: target, since: new Date().toISOString(), from: me });
    return json({ ok: true, message: `${rec.name} is now the owner. You're an admin.` });
  }
  if ((action === "promote" || action === "demote") && !iAmOwner)
    return json({ error: "Only the owner can add or remove admins" }, 403);
  if (["reset", "signout", "disable", "enable", "delete"].includes(action) && !canManage)
    return json({ error: self ? "You can't do that to your own account" : "Only the owner can change admin accounts" }, 403);
  if (target === owner && action !== "signout")
    return json({ error: "Give ownership to someone else first" }, 400);

  switch (action) {
    case "reset": {
      const pw = clip(body.password, 200);
      if (pw.length < 6) return json({ error: "New password needs at least 6 characters" }, 400);
      setPw(rec, pw);
      rec.assigned = pw;
      rec.tv = (rec.tv ?? 0) + 1;
      await putUser(target, rec);
      return json({ ok: true, message: `Password reset for ${rec.name}. They've been signed out.` });
    }
    case "signout": {
      rec.tv = (rec.tv ?? 0) + 1;
      await putUser(target, rec);
      return json({ ok: true, message: `${rec.name} was signed out on every device.` });
    }
    case "disable":
    case "enable": {
      if (self) return json({ error: "You can't turn off your own account" }, 400);
      if (locked && action === "disable") return json({ error: "This admin is set in Netlify and can't be turned off here" }, 400);
      rec.disabled = action === "disable";
      if (rec.disabled) rec.tv = (rec.tv ?? 0) + 1;
      await putUser(target, rec);
      return json({ ok: true, message: `${rec.name} ${rec.disabled ? "can no longer sign in" : "can sign in again"}.` });
    }
    case "promote":
    case "demote": {
      if (action === "demote" && (self || locked))
        return json({ error: self ? "You can't remove your own admin access" : "This admin is set in Netlify and can't be removed here" }, 400);
      rec.admin = action === "promote";
      await putUser(target, rec);
      return json({ ok: true, message: `${rec.name} is ${rec.admin ? "now an admin" : "no longer an admin"}.` });
    }
    case "delete": {
      if (self) return json({ error: "You can't delete your own account" }, 400);
      if (locked) return json({ error: "This admin is set in Netlify and can't be deleted here" }, 400);
      let removed = 0;
      if (body.withNotes === true) {
        const s = notesStore();
        for (const n of await allNotes()) {
          if (n.author === target) {
            await s.delete(n.id);
            removed++;
          }
        }
      }
      await usersStore().delete(target);
      return json({ ok: true, message: `Deleted ${rec.name}${body.withNotes ? ` and ${removed} note${removed === 1 ? "" : "s"}` : ""}.` });
    }
  }
  return json({ error: "Unknown action" }, 400);
}

export default async (req: Request, context: Context) => {
  const path = new URL(req.url).pathname;
  try {
    if (path === "/api/signup" && req.method === "POST") return await signup(req);
    if (path === "/api/login" && req.method === "POST") return await login(req);

    const who = await readToken(req);
    if (!who) return json({ error: "Please sign in" }, 401);
    const { user, rec } = who;
    const owner = await getOwner();
    const admin = isAdmin(user, rec, owner);

    if (path === "/api/me") return json({ user, name: rec.name || user, admin, owner: user === owner });
    if (path === "/api/notes") {
      if (req.method === "GET") return json({ notes: await allNotes() });
      if (req.method === "POST") return await addNotes(req, user, rec);
      if (req.method === "DELETE") return await deleteNote(req, user, admin);
    }
    if (path === "/api/admin") {
      if (!admin) return json({ error: "Admins only" }, 403);
      if (req.method === "GET") return await listUsers(user);
      if (req.method === "POST") return await adminAction(req, user, owner);
    }
    return json({ error: "Not found" }, 404);
  } catch (e) {
    console.error(e);
    return json({ error: "Server error" }, 500);
  }
};

export const config: Config = {
  path: ["/api/notes", "/api/signup", "/api/login", "/api/me", "/api/admin"],
  method: ["GET", "POST", "DELETE"],
};
