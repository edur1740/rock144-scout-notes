import type { Config, Context } from "@netlify/functions";
import { getStore } from "@netlify/blobs";
import { createHash, createHmac, createPrivateKey, generateKeyPairSync, randomBytes, scryptSync, sign as cryptoSign, timingSafeEqual } from "node:crypto";

const notesStore = () => getStore({ name: "scout-notes", consistency: "strong" });
const usersStore = () => getStore({ name: "scout-users", consistency: "strong" });
const configStore = () => getStore({ name: "scout-config", consistency: "strong" });
const pushStore = () => getStore({ name: "push-subs", consistency: "strong" });
const limitStore = () => getStore({ name: "rate-limits", consistency: "strong" });

/* ---------- rate limiting: slow down password and team-code guessing ---------- */
const WINDOW_MS = 15 * 60 * 1000;
// Wrong tries allowed per 15 minutes. The tight per-account limit only applies to the
// network doing the guessing, so a prankster can't lock a real scout out of their account.
const LIMITS = { userNet: 5, user: 30, ip: 60, code: 5, newAccounts: 15 }; // ip is high because a whole team often shares one Wi-Fi
const limitKey = (kind: string, id: string) => `${kind}-${createHash("sha256").update(id).digest("hex").slice(0, 32)}`;
const clientId = (req: Request, context: Context) =>
  (context as any)?.ip || req.headers.get("x-nf-client-connection-ip") || req.headers.get("x-forwarded-for")?.split(",")[0].trim() || "unknown";
async function recentFails(key: string): Promise<number[]> {
  const v: any = await limitStore().get(key, { type: "json" });
  const now = Date.now();
  return (Array.isArray(v?.fails) ? v.fails : []).filter((t: number) => now - t < WINDOW_MS);
}
async function blockedFor(key: string, max: number): Promise<number> {
  const f = await recentFails(key);
  if (f.length < max) return 0;
  return Math.max(1, Math.ceil((Math.min(...f) + WINDOW_MS - Date.now()) / 60000)); // minutes left
}
async function addFail(key: string) {
  const f = await recentFails(key);
  f.push(Date.now());
  await limitStore().setJSON(key, { fails: f.slice(-(Math.max(...Object.values(LIMITS)) + 5)) }); // keep enough to reach the highest limit
}
const tooMany = (mins: number) =>
  json({ error: `Too many wrong tries. Wait ${mins} minute${mins === 1 ? "" : "s"} and try again.` }, 429);

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
    },
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

async function getSettings(): Promise<{ signupsOpen: boolean; scheduleOn: boolean }> {
  const v: any = await configStore().get("settings", { type: "json" });
  return { signupsOpen: v?.signupsOpen !== false, scheduleOn: v?.scheduleOn === true };
}
async function saveSettings(patch: Partial<{ signupsOpen: boolean; scheduleOn: boolean }>) {
  await configStore().setJSON("settings", { ...(await getSettings()), ...patch });
}
const signupsOpen = async () => (await getSettings()).signupsOpen;

/* ---------- scouting schedule ---------- */
const SLOTS = ["R1", "R2", "R3", "B1", "B2", "B3"];
type Block = { id: string; from: number; to: number; slots: Record<string, string>; watches: { team: string; scout: string }[]; note: string };

const EV_RE = /^[a-z0-9]{4,40}$/;
const goodId = (v: unknown) => typeof v === "string" && EV_RE.test(v) && v !== "undefined" && v !== "null";
const schedKey = (ev: string) => `schedule-${goodId(ev) ? ev : "none"}`;
async function getSchedule(ev: string): Promise<Block[]> {
  const v: any = await configStore().get(schedKey(ev), { type: "json" });
  return Array.isArray(v?.blocks) ? v.blocks : [];
}

/* ---------- events ---------- */
type Ev = { id: string; name: string; start: string; end: string; location: string; teams: string[] };
async function getEvents(): Promise<{ events: Ev[]; current: string | null }> {
  const v: any = await configStore().get("events", { type: "json" });
  return { events: Array.isArray(v?.events) ? v.events : [], current: v?.current ?? null };
}
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
function cleanEvents(input: unknown): Ev[] {
  if (!Array.isArray(input)) return [];
  return input.slice(0, 100).map((e: any) => ({
    id: goodId(e?.id) ? e.id : randomBytes(6).toString("hex"),
    name: clip(e?.name, 80).trim(),
    start: DATE_RE.test(e?.start) ? e.start : "",
    end: DATE_RE.test(e?.end) ? e.end : "",
    location: clip(e?.location, 80).trim(),
    teams: [...new Set((Array.isArray(e?.teams) ? e.teams : []).slice(0, 120).map((t: unknown) => clip(t, 6).replace(/\D/g, "")).filter(Boolean))] as string[],
  })).filter((e) => e.name);
}
function cleanBlocks(input: unknown): Block[] {
  if (!Array.isArray(input)) return [];
  return input.slice(0, 200).map((b: any) => {
    const from = Math.max(0, Math.min(999, parseInt(b?.from) || 0));
    const to = Math.max(from, Math.min(999, parseInt(b?.to) || from));
    const slots: Record<string, string> = {};
    for (const s of SLOTS) {
      const u = clip(b?.slots?.[s], 20).toLowerCase();
      if (USER_RE.test(u)) slots[s] = u;
    }
    const watches = (Array.isArray(b?.watches) ? b.watches : []).slice(0, 12)
      .map((w: any) => ({ team: clip(w?.team, 6).replace(/\D/g, ""), scout: clip(w?.scout, 20).toLowerCase() }))
      .filter((w: any) => w.team && USER_RE.test(w.scout));
    const id = goodId(b?.id) ? b.id : randomBytes(6).toString("hex");
    return { id, from, to, slots, watches, note: clip(b?.note, 200) };
  }).filter((b) => b.from > 0).sort((a, b) => a.from - b.from);
}
async function scheduleView(admin: boolean, ev: string) {
  const { scheduleOn } = await getSettings();
  if (!scheduleOn && !admin) return json({ on: false, blocks: [], names: {} });
  const blocks = await getSchedule(ev);
  const s = usersStore();
  const { blobs } = await s.list();
  const names: Record<string, string> = {};
  await Promise.all(blobs.map(async ({ key }) => {
    const r = (await s.get(key, { type: "json" })) as UserRec | null;
    if (r && !r.disabled) names[key] = r.name || key;
  }));
  return json({ on: scheduleOn, event: ev, blocks, names });
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

/* ---------- phone alerts (Web Push, no payload) ---------- */
// VAPID keys are made once and kept in Blobs, so no setup is needed.
async function getVapid(): Promise<{ pub: string; jwk: any }> {
  const s = configStore();
  let v: any = await s.get("vapid", { type: "json" });
  if (!v) {
    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const pj: any = publicKey.export({ format: "jwk" });
    const pub = Buffer.concat([Buffer.from([4]), Buffer.from(pj.x, "base64url"), Buffer.from(pj.y, "base64url")]).toString("base64url");
    await s.setJSON("vapid", { pub, jwk: privateKey.export({ format: "jwk" }) }, { onlyIfNew: true });
    v = await s.get("vapid", { type: "json" });
  }
  return v;
}
async function sendPush(endpoint: string): Promise<number> {
  const { pub, jwk } = await getVapid();
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const unsigned = `${enc({ typ: "JWT", alg: "ES256" })}.${enc({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: "https://rock-scout-notes.netlify.app" })}`;
  const sig = cryptoSign("sha256", Buffer.from(unsigned), { key: createPrivateKey({ key: jwk, format: "jwk" }), dsaEncoding: "ieee-p1363" }).toString("base64url");
  const r = await fetch(endpoint, {
    method: "POST",
    headers: { TTL: "86400", Urgency: "high", Authorization: `vapid t=${unsigned}.${sig}, k=${pub}`, "Content-Length": "0" },
  });
  return r.status;
}
const subKey = (endpoint: string) => createHash("sha256").update(endpoint).digest("hex").slice(0, 40);
async function pushTo(filter: (user: string) => Promise<boolean>) {
  const s = pushStore();
  const { blobs } = await s.list();
  let sent = 0;
  await Promise.all(blobs.map(async ({ key }) => {
    const sub: any = await s.get(key, { type: "json" });
    if (!sub?.endpoint || !(await filter(sub.user))) return;
    try {
      const st = await sendPush(sub.endpoint);
      if (st === 404 || st === 410) await s.delete(key); // phone unsubscribed
      else if (st < 300) sent++;
    } catch (e) { console.error("push failed", e); }
  }));
  return sent;
}
async function notifyAdminsOfJoin() {
  const owner = await getOwner();
  return pushTo(async (u) => {
    const rec = await getUser(u);
    return !!rec && !rec.disabled && isAdmin(u, rec, owner);
  });
}
async function recentJoins() {
  const s = usersStore();
  const { blobs } = await s.list();
  const all = await Promise.all(blobs.map(async ({ key }) => {
    const r = (await s.get(key, { type: "json" })) as UserRec | null;
    return r ? { user: key, name: r.name || key, created: r.created, self: !r.assigned && !r.createdBy } : null;
  }));
  return (all.filter(Boolean) as any[]).sort((a, b) => String(b.created).localeCompare(String(a.created))).slice(0, 10);
}

async function signup(req: Request, context: Context) {
  const body = await req.json().catch(() => ({}));
  const code = Netlify.env.get("TEAM_CODE");
  if (!(await signupsOpen())) return json({ error: "Sign-up is closed. Ask your scouting lead for a login." }, 403);
  const codeKey = limitKey("code", clientId(req, context));
  const codeWait = await blockedFor(codeKey, LIMITS.code);
  if (codeWait) return tooMany(codeWait);
  if (!code || clip(body.code, 100).trim() !== code) {
    await addFail(codeKey);
    return json({ error: "Wrong team code" }, 401);
  }
  const name = clip(body.username, 20).trim();
  const user = name.toLowerCase();
  const pw = clip(body.password, 200);
  if (!USER_RE.test(user)) return json({ error: "Username: 3–20 letters, numbers or _" }, 400);
  if (pw.length < 6) return json({ error: "Password needs at least 6 characters" }, 400);
  // Bot protection: one network can only make so many accounts in 15 minutes
  // (high enough for a whole team signing up on school Wi-Fi together).
  const newKey = limitKey("newacct", clientId(req, context));
  const newWait = await blockedFor(newKey, LIMITS.newAccounts);
  if (newWait) return json({ error: `Lots of accounts were just made on this network. Try again in ${newWait} minute${newWait === 1 ? "" : "s"}, or ask a lead to make yours.` }, 429);
  const rec: UserRec = { name, salt: "", hash: "", created: new Date().toISOString(), tv: 0 };
  setPw(rec, pw);
  const { modified } = await usersStore().setJSON(user, rec, { onlyIfNew: true });
  if (!modified) return json({ error: "That username is taken" }, 409);
  await addFail(newKey); // counts accounts made, not failures
  const owner = await getOwner();
  const alert = notifyAdminsOfJoin().catch((e) => console.error(e));
  if (typeof (context as any)?.waitUntil === "function") (context as any).waitUntil(alert);
  else await alert;
  return json({ token: await makeToken(user, 0), user, name, admin: isAdmin(user, rec, owner), owner: user === owner });
}

async function login(req: Request, context: Context) {
  const body = await req.json().catch(() => ({}));
  const user = clip(body.username, 20).trim().toLowerCase();
  const pw = clip(body.password, 200);
  const net = clientId(req, context);
  const ipKey = limitKey("ip", net);
  const userNetKey = limitKey("usernet", `${user || "-"}|${net}`);
  const userKey = limitKey("user", user || "-");
  const wait = Math.max(
    await blockedFor(ipKey, LIMITS.ip),
    await blockedFor(userNetKey, LIMITS.userNet),
    await blockedFor(userKey, LIMITS.user),
  );
  if (wait) return tooMany(wait);
  const fail = async () => {
    await Promise.all([addFail(ipKey), addFail(userNetKey), addFail(userKey)]);
    return json({ error: "Wrong username or password" }, 401);
  };
  const rec = USER_RE.test(user) ? await getUser(user) : null;
  if (!rec) return fail();
  const a = Buffer.from(hashPw(pw, rec.salt), "hex"), b = Buffer.from(rec.hash, "hex");
  if (a.length !== b.length || !timingSafeEqual(a, b)) return fail();
  await limitStore().delete(userNetKey); // a correct password clears this network's count
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
  const currentEv = (await getEvents()).current;
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
      event: currentEv || "",
      at: new Date().toISOString(),
    };
    await s.setJSON(id, note, { onlyIfNew: true });
    saved.push(id);
  }
  return json({ saved }, 201);
}

/* ---------- backup & restore (owner only) ----------
   A backup is one file with every note, event, schedule and account.
   It never contains readable passwords (only the scrambled form, so restored accounts can still sign in),
   the app's signing secret, or phone-alert keys. Restoring only ADDS what's missing; it never overwrites. */
const HEX_RE = /^[0-9a-f]{16,256}$/;
const ISO = (v: unknown) => (typeof v === "string" && !isNaN(Date.parse(v)) ? new Date(v).toISOString() : new Date().toISOString());
async function inChunks<T>(items: T[], fn: (x: T) => Promise<unknown>, size = 25) {
  for (let i = 0; i < items.length; i += size) await Promise.all(items.slice(i, i + size).map(fn));
}

async function makeBackup(by: string) {
  const us = usersStore();
  const users: any[] = [];
  await inChunks((await us.list()).blobs, async ({ key }) => {
    const r = (await us.get(key, { type: "json" })) as UserRec | null;
    if (!r) return;
    users.push({ user: key, name: r.name, salt: r.salt, hash: r.hash, created: r.created, admin: !!r.admin, disabled: !!r.disabled, createdBy: r.createdBy });
  });
  const ev = await getEvents();
  const schedules: Record<string, Block[]> = {};
  for (const e of ev.events) { const b = await getSchedule(e.id); if (b.length) schedules[e.id] = b; }
  const none = await getSchedule("none");
  if (none.length) schedules.none = none;
  return {
    app: "rock-scout-notes", version: 1, made: new Date().toISOString(), by,
    notes: await allNotes(), events: ev, schedules, settings: await getSettings(), users,
  };
}

async function restoreBackup(req: Request) {
  const b: any = await req.json().catch(() => null);
  if (!b || typeof b !== "object" || b.app !== "rock-scout-notes" || b.version !== 1)
    return json({ error: "That file isn't a Scout Notes backup." }, 400);
  const added = { notes: 0, accounts: 0, events: 0, schedules: 0 };

  // Notes: put back any that are missing, exactly as they were.
  const ns = notesStore();
  const notes = (Array.isArray(b.notes) ? b.notes : []).slice(0, 20000);
  await inChunks(notes, async (n: any) => {
    const id = clip(n?.id, 40).toLowerCase();
    const team = clip(n?.team, 6).replace(/\D/g, "");
    if (!ID_RE.test(id) || !team) return;
    const author = clip(n.author, 20).toLowerCase();
    const note = {
      team, match: clip(n.match, 10), author: USER_RE.test(author) ? author : "",
      scout: clip(n.scout, 40), tags: Array.isArray(n.tags) ? n.tags.slice(0, 12).map((t: unknown) => clip(t, 40)) : [],
      text: clip(n.text, 2000), event: goodId(n.event) ? n.event : "", at: ISO(n.at),
    };
    const { modified } = await ns.setJSON(id, note, { onlyIfNew: true });
    if (modified) added.notes++;
  });

  // Accounts: put back any that were deleted. Existing accounts are left alone.
  await inChunks((Array.isArray(b.users) ? b.users : []).slice(0, 2000), async (u: any) => {
    const user = clip(u?.user, 20).toLowerCase();
    if (!USER_RE.test(user) || !HEX_RE.test(String(u.salt)) || !HEX_RE.test(String(u.hash))) return;
    const rec: UserRec = {
      name: clip(u.name, 20).trim() || user, salt: u.salt, hash: u.hash, created: ISO(u.created),
      admin: u.admin === true, disabled: u.disabled === true,
      tv: 1 + Math.floor(Math.random() * 1e6), // any old sign-ins from before the delete stay signed out
      createdBy: USER_RE.test(String(u.createdBy)) ? u.createdBy : undefined,
    };
    const { modified } = await usersStore().setJSON(user, rec, { onlyIfNew: true });
    if (modified) added.accounts++;
  });

  // Events: add the ones that are missing. Keep the current event as it is now (unless none is set).
  const now = await getEvents();
  const have = new Set(now.events.map((e) => e.id));
  const restored = cleanEvents(b.events?.events).filter((e) => !have.has(e.id) && b.events.events.some((x: any) => x?.id === e.id));
  if (restored.length) {
    const events = [...now.events, ...restored].slice(0, 100);
    const cur = now.current ?? (events.some((e) => e.id === b.events?.current) ? b.events.current : null);
    await configStore().setJSON("events", { events, current: cur });
    added.events = restored.length;
  }

  // Schedules: only fill in events that have no schedule right now.
  for (const [ev, blocks] of Object.entries(b.schedules && typeof b.schedules === "object" ? b.schedules : {}).slice(0, 100)) {
    if (ev !== "none" && !goodId(ev)) continue;
    if ((await getSchedule(ev)).length) continue;
    const clean = cleanBlocks(blocks);
    if (!clean.length) continue;
    await configStore().setJSON(schedKey(ev), { blocks: clean, updated: new Date().toISOString(), by: "restore" });
    added.schedules++;
  }

  const parts = [`${added.notes} note${added.notes === 1 ? "" : "s"}`, `${added.accounts} account${added.accounts === 1 ? "" : "s"}`,
    `${added.events} event${added.events === 1 ? "" : "s"}`, `${added.schedules} schedule${added.schedules === 1 ? "" : "s"}`];
  return json({ ok: true, added, message: `Restored ${parts.join(", ")}. Anything already in the app was left as it is.` });
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
    await saveSettings({ signupsOpen: open });
    return json({ ok: true, message: open ? "Scouts can sign up with the team code." : "Sign-up is closed. Only you and admins can make accounts." });
  }
  if (action === "forceUpdate") {
    if (!iAmOwner) return json({ error: "Only the owner can update everyone's app" }, 403);
    await configStore().setJSON("force-update", { token: randomBytes(6).toString("hex"), at: new Date().toISOString(), by: me });
    return json({ ok: true, message: "Done. Every open app will reload within about 15 seconds." });
  }
  if (action === "scheduleTab") {
    if (!iAmOwner) return json({ error: "Only the owner can turn the Schedule tab on or off" }, 403);
    const on = body.on === true;
    await saveSettings({ scheduleOn: on });
    return json({ ok: true, message: on ? "Scouts can now see the Schedule tab." : "The Schedule tab is hidden from scouts." });
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
    if (path === "/api/signup" && req.method === "POST") return await signup(req, context);
    if (path === "/api/login" && req.method === "POST") return await login(req, context);

    const who = await readToken(req);
    if (!who) return json({ error: "Please sign in" }, 401);
    const { user, rec } = who;
    const owner = await getOwner();
    const admin = isAdmin(user, rec, owner);

    if (path === "/api/me")
      return json({ user, name: rec.name || user, admin, owner: user === owner, scheduleOn: (await getSettings()).scheduleOn, joins: admin ? await recentJoins() : [] });
    if (path === "/api/account" && req.method === "POST") {
      // A scout deletes their own account (password required).
      const body: any = await req.json().catch(() => ({}));
      if (body.action !== "delete") return json({ error: "Unknown action" }, 400);
      if (user === owner) return json({ error: "You're the owner. Give ownership to someone else on the Accounts tab first." }, 400);
      const userNetKey = limitKey("usernet", `${user}|${clientId(req, context)}`);
      const wait = await blockedFor(userNetKey, LIMITS.userNet);
      if (wait) return tooMany(wait);
      const a = Buffer.from(hashPw(clip(body.password, 200), rec.salt), "hex"), b = Buffer.from(rec.hash, "hex");
      if (a.length !== b.length || !timingSafeEqual(a, b)) {
        await addFail(userNetKey);
        return json({ error: "That password isn't right." }, 401);
      }
      let removed = 0;
      if (body.withNotes === true) {
        for (const n of await allNotes()) if (n.author === user) { await notesStore().delete(n.id); removed++; }
      }
      const ps = pushStore();
      for (const { key } of (await ps.list()).blobs) { const s: any = await ps.get(key, { type: "json" }); if (s?.user === user) await ps.delete(key); }
      await usersStore().delete(user);
      return json({ ok: true, removed });
    }
    if (path === "/api/team") {
      // Everyone signed in can see the crew: names, roles, join dates, note counts. No passwords or usernames.
      const s = usersStore();
      const { blobs } = await s.list();
      const counts: Record<string, number> = {};
      (await allNotes()).forEach((n: any) => n.author && (counts[n.author] = (counts[n.author] || 0) + 1));
      const members = (await Promise.all(blobs.map(async ({ key }) => {
        const r = (await s.get(key, { type: "json" })) as UserRec | null;
        if (!r || r.disabled) return null;
        return { name: r.name || key, role: key === owner ? "owner" : isAdmin(key, r, owner) ? "admin" : "scout", joined: r.created, notes: counts[key] || 0, me: key === user };
      }))).filter(Boolean);
      return json({ members });
    }
    if (path === "/api/push") {
      if (!admin) return json({ error: "Join alerts are for admins" }, 403);
      const body: any = req.method === "POST" ? await req.json().catch(() => ({})) : {};
      if (req.method === "GET") {
        const { blobs } = await pushStore().list();
        let mine = 0;
        for (const { key } of blobs) { const s: any = await pushStore().get(key, { type: "json" }); if (s?.user === user) mine++; }
        return json({ key: (await getVapid()).pub, devices: mine });
      }
      if (body.action === "subscribe") {
        const ep = clip(body.endpoint, 1000);
        if (!/^https:\/\//.test(ep)) return json({ error: "Bad subscription" }, 400);
        await pushStore().setJSON(subKey(ep), { user, endpoint: ep, created: new Date().toISOString() });
        return json({ ok: true });
      }
      if (body.action === "unsubscribe") {
        await pushStore().delete(subKey(clip(body.endpoint, 1000)));
        return json({ ok: true });
      }
      if (body.action === "test") {
        const n = await pushTo(async (u) => u === user);
        return json({ ok: true, sent: n });
      }
      return json({ error: "Unknown action" }, 400);
    }
    if (path === "/api/schedule") {
      const evq = new URL(req.url).searchParams.get("event") || (await getEvents()).current || "none";
      if (req.method === "GET") return await scheduleView(admin, evq);
      if (req.method === "POST") {
        if (!admin) return json({ error: "Only admins can change the schedule" }, 403);
        const body = await req.json().catch(() => ({}));
        const blocks = cleanBlocks(body.blocks);
        await configStore().setJSON(schedKey(evq), { blocks, updated: new Date().toISOString(), by: user });
        return json({ ok: true, blocks });
      }
    }
    if (path === "/api/myschedule") {
      const { scheduleOn } = await getSettings();
      if (!scheduleOn && !admin) return json({ on: false, events: [] });
      const { events, current } = await getEvents();
      const out = [];
      for (const e of events) {
        const blocks = (await getSchedule(e.id))
          .map((b) => ({
            from: b.from,
            to: b.to,
            note: b.note,
            slots: Object.entries(b.slots).filter(([, u]) => u === user).map(([k]) => k),
            teams: (b.watches || []).filter((w) => w.scout === user).map((w) => w.team),
          }))
          .filter((b) => b.slots.length || b.teams.length);
        if (blocks.length) out.push({ id: e.id, name: e.name, start: e.start, end: e.end, location: e.location, current: e.id === current, blocks });
      }
      return json({ on: scheduleOn, events: out });
    }
    if (path === "/api/events") {
      if (req.method === "GET") return json(await getEvents());
      if (req.method === "POST") {
        if (!admin) return json({ error: "Only admins can change events" }, 403);
        const body = await req.json().catch(() => ({}));
        const events = cleanEvents(body.events);
        const current = events.some((e) => e.id === body.current) ? body.current : null;
        await configStore().setJSON("events", { events, current });
        return json({ events, current });
      }
    }
    if (path === "/api/notes") {
      if (req.method === "GET") {
        const f: any = await configStore().get("force-update", { type: "json" });
        return json({ notes: await allNotes(), force: f?.token ?? "" });
      }
      if (req.method === "POST") return await addNotes(req, user, rec);
      if (req.method === "DELETE") return await deleteNote(req, user, admin);
    }
    if (path === "/api/backup") {
      if (user !== owner) return json({ error: "Only the owner can make or restore backups" }, 403);
      if (req.method === "GET") return json(await makeBackup(user));
      if (req.method === "POST") return await restoreBackup(req);
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
  path: ["/api/notes", "/api/signup", "/api/login", "/api/me", "/api/admin", "/api/schedule", "/api/events", "/api/myschedule", "/api/push", "/api/team", "/api/account", "/api/backup"],
  method: ["GET", "POST", "DELETE"],
};
