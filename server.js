import express from 'express';
import cookieParser from 'cookie-parser';
import { createClient } from '@supabase/supabase-js';
import { ImapFlow } from 'imapflow';
import { simpleParser } from 'mailparser';
import fs from 'node:fs/promises';
import path from 'node:path';

const app = express();
const port = Number(process.env.PORT || 5173);
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseAnonKey || !serviceRoleKey) {
  throw new Error('Supabase server configuration is missing');
}

const authClient = createClient(supabaseUrl, supabaseAnonKey, { auth: { autoRefreshToken: false, persistSession: false } });
const adminClient = createClient(supabaseUrl, serviceRoleKey, { auth: { autoRefreshToken: false, persistSession: false } });
const stopRequests = new Set();
const runningRuns = new Map();

app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use(express.static(process.cwd()));

function publicProfile(profile) {
  return {
    authenticated: true,
    email: profile.email,
    role: profile.role,
    mailboxes: profile.mailboxes || '',
    created_at: profile.created_at,
    mailbox_count: (profile.mailboxes || '').split('\n').filter(Boolean).length,
  };
}

async function getRequestUser(req) {
  const token = req.cookies.session;
  if (!token) return null;
  const { data, error } = await authClient.auth.getUser(token);
  if (error || !data.user) return null;
  const { data: profile } = await adminClient.from('profiles').select('id,email,role,mailboxes,created_at').eq('id', data.user.id).maybeSingle();
  return profile ? { user: data.user, profile, token } : null;
}

async function requireUser(req, res, next) {
  const identity = await getRequestUser(req);
  if (!identity) return res.status(401).json({ error: 'Not signed in' });
  req.identity = identity;
  next();
}

async function requireAdmin(req, res, next) {
  await requireUser(req, res, () => {
    if (req.identity.profile.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    next();
  });
}

async function ensureProfile(user) {
  const { data: existing } = await adminClient.from('profiles').select('id').eq('id', user.id).maybeSingle();
  if (existing) return;
  await adminClient.from('profiles').insert({ id: user.id, email: user.email || '', role: 'user' });
}

app.get('/', async (_req, res) => res.sendFile(path.join(process.cwd(), 'index.html')));
app.get('/admin', async (_req, res) => res.sendFile(path.join(process.cwd(), 'mailbox hit checker', 'templates', 'admin.html')));

app.get('/api/me', async (req, res) => {
  const identity = await getRequestUser(req);
  if (!identity) return res.json({ authenticated: false, role: null, email: null });
  res.json(publicProfile(identity.profile));
});

app.post('/api/signup', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  if (!/^\\S+@\\S+\\.\\S+$/.test(email) || password.length < 6) return res.status(400).json({ error: 'Use a valid email and a password of at least 6 characters' });
  const { count } = await adminClient.from('profiles').select('id', { count: 'exact', head: true });
  const role = count === 0 ? 'admin' : 'user';
  const { data, error } = await adminClient.auth.admin.createUser({ email, password, email_confirm: true });
  if (error || !data.user) return res.status(400).json({ error: 'Could not create account' });
  const { error: profileError } = await adminClient.from('profiles').insert({ id: data.user.id, email, role });
  if (profileError) { await adminClient.auth.admin.deleteUser(data.user.id); return res.status(400).json({ error: 'Could not create account' }); }
  const { data: sessionData, error: loginError } = await authClient.auth.signInWithPassword({ email, password });
  if (loginError || !sessionData.session) return res.status(500).json({ error: 'Account created, but sign-in could not be completed' });
  res.cookie('session', sessionData.session.access_token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 8 });
  res.json({ status: 'created', email, role });
});

app.post('/api/login', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  const { data, error } = await authClient.auth.signInWithPassword({ email, password });
  if (error || !data.session || !data.user) return res.status(401).json({ error: 'Invalid email or password' });
  await ensureProfile(data.user);
  const { data: profile } = await adminClient.from('profiles').select('email,role,mailboxes,created_at').eq('id', data.user.id).maybeSingle();
  res.cookie('session', data.session.access_token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 8 });
  res.json({ status: 'ok', email: profile?.email || email, role: profile?.role || 'user' });
});

app.post('/api/admin/login', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  const { data, error } = await authClient.auth.signInWithPassword({ email, password });
  if (error || !data.session || !data.user) return res.status(401).json({ error: 'Invalid credentials' });
  await ensureProfile(data.user);
  const { data: profile } = await adminClient.from('profiles').select('email,role').eq('id', data.user.id).maybeSingle();
  if (!profile || profile.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  res.cookie('session', data.session.access_token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 8 });
  res.json({ status: 'ok', email: profile.email, role: profile.role });
});

app.post('/api/logout', (_req, res) => { res.clearCookie('session'); res.json({ status: 'ok' }); });

app.post('/api/save_mailboxes', requireUser, async (req, res) => {
  const mailboxes = String(req.body?.mailboxes || '');
  const { error } = await adminClient.from('profiles').update({ mailboxes }).eq('id', req.identity.user.id);
  if (error) return res.status(500).json({ error: 'Could not save mailboxes' });
  res.json({ status: 'saved', mailbox_count: mailboxes.split('\n').filter((line) => line.trim()).length, saved_at: new Date().toISOString() });
});

app.get('/api/tests', requireUser, async (req, res) => {
  const { data, error } = await adminClient.from('test_presets').select('name,inputs,saved_at').eq('user_id', req.identity.user.id).order('saved_at', { ascending: true });
  if (error) return res.status(500).json({ error: 'Could not load saved tests' });
  res.json({ tests: data || [] });
});

app.post('/api/tests', requireUser, async (req, res) => {
  const name = String(req.body?.name || '').trim();
  const inputs = String(req.body?.inputs || '');
  if (!name) return res.status(400).json({ error: 'Test name required' });
  const { error } = await adminClient.from('test_presets').upsert({ user_id: req.identity.user.id, name, inputs, saved_at: new Date().toISOString() }, { onConflict: 'user_id,name' });
  if (error) return res.status(500).json({ error: 'Could not save test' });
  const { data } = await adminClient.from('test_presets').select('name,inputs,saved_at').eq('user_id', req.identity.user.id).order('saved_at', { ascending: true });
  res.json({ status: 'saved', tests: data || [] });
});

app.post('/api/tests/delete', requireUser, async (req, res) => {
  const name = String(req.body?.name || '').trim();
  const { error } = await adminClient.from('test_presets').delete().eq('user_id', req.identity.user.id).eq('name', name);
  if (error) return res.status(500).json({ error: 'Could not delete test' });
  const { data } = await adminClient.from('test_presets').select('name,inputs,saved_at').eq('user_id', req.identity.user.id).order('saved_at', { ascending: true });
  res.json({ status: 'deleted', tests: data || [] });
});

app.get('/api/admin/users', requireAdmin, async (_req, res) => {
  const { data, error } = await adminClient.from('profiles').select('id,email,role,created_at,mailboxes').neq('role', 'admin').order('created_at', { ascending: true });
  if (error) return res.status(500).json({ error: 'Could not load users' });
  res.json({ users: (data || []).map((user) => ({ ...user, mailbox_count: (user.mailboxes || '').split('\n').filter(Boolean).length })) });
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const { data, error } = await adminClient.auth.admin.createUser({ email, password, email_confirm: true });
  if (error || !data.user) return res.status(400).json({ error: 'Could not create account' });
  const { error: profileError } = await adminClient.from('profiles').insert({ id: data.user.id, email, role: 'user' });
  if (profileError) { await adminClient.auth.admin.deleteUser(data.user.id); return res.status(400).json({ error: 'Could not create account' }); }
  res.json({ status: 'created', email });
});

app.post('/api/admin/users/delete', requireAdmin, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const { data: profile } = await adminClient.from('profiles').select('id,role').eq('email', email).maybeSingle();
  if (!profile || profile.role === 'admin') return res.status(400).json({ error: 'Cannot delete this account' });
  const { error } = await adminClient.auth.admin.deleteUser(profile.id);
  if (error) return res.status(400).json({ error: 'Could not delete account' });
  res.json({ status: 'deleted', email });
});

app.post('/api/admin/users/reset', requireAdmin, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const { data: profile } = await adminClient.from('profiles').select('id,role').eq('email', email).maybeSingle();
  if (!profile || profile.role === 'admin') return res.status(400).json({ error: 'Cannot reset this account' });
  const { error } = await adminClient.auth.admin.updateUserById(profile.id, { password });
  if (error) return res.status(400).json({ error: 'Could not reset account' });
  res.json({ status: 'reset', email });
});

function parseMailboxLine(line) {
  const separator = line.indexOf(':');
  if (separator <= 0) return null;
  return { email: line.slice(0, separator).trim(), password: line.slice(separator + 1).trim() };
}

function hostForEmail(email) {
  const domain = email.split('@')[1]?.toLowerCase();
  const hosts = { 'gmail.com': 'imap.gmail.com', 'outlook.com': 'outlook.office365.com', 'hotmail.com': 'outlook.office365.com', 'yahoo.com': 'imap.mail.yahoo.com', 'aol.com': 'imap.aol.com', 'icloud.com': 'imap.mail.me.com' };
  return hosts[domain] || `imap.${domain}`;
}

async function scanMailbox(mailbox, inputs, runId, runState) {
  const client = new ImapFlow({ host: hostForEmail(mailbox.email), port: 993, secure: true, auth: { user: mailbox.email, pass: mailbox.password }, logger: false });
  const result = { email: mailbox.email, status: 'running', error: null, folders: {}, inbox: inputs.map(() => 0), spam: inputs.map(() => 0), previews: { inbox: inputs.map(() => []), spam: inputs.map(() => []) }, inbox_total: 0, spam_total: 0 };
  try {
    await client.connect();
    const listed = await client.list();
    const folders = listed.filter((folder) => /inbox|spam|junk/i.test(folder.path));
    for (const folder of folders) {
      if (stopRequests.has(runId)) break;
      const bucket = /spam|junk/i.test(folder.path) ? 'spam' : 'inbox';
      const lock = await client.getMailboxLock(folder.path);
      try {
        const uids = await client.search({ all: true });
        for (const uid of uids) {
          if (stopRequests.has(runId)) break;
          const message = await client.fetchOne(uid, { source: true, envelope: true });
          const parsed = await simpleParser(message.source);
          const haystack = `${parsed.subject || ''}\n${parsed.from?.text || ''}\n${parsed.text || ''}`.toLowerCase();
          const preview = { subject: parsed.subject || '(no subject)', from: parsed.from?.text || '', date: parsed.date?.toISOString() || '' };
          for (let index = 0; index < inputs.length; index += 1) {
            if (!haystack.includes(inputs[index].toLowerCase())) continue;
            result[bucket][index] += 1;
            if (result.previews[bucket][index].length < 5) result.previews[bucket][index].push(preview);
          }
          result[`${bucket}_total`] += 1;
          runState.current = `${mailbox.email} · ${folder.path}`;
          runState.progress += 1;
        }
      } finally { lock.release(); }
    }
    result.status = stopRequests.has(runId) ? 'stopped' : 'ok';
  } catch (_error) { result.status = 'error'; result.error = 'Mailbox connection failed'; }
  finally { await client.logout().catch(() => {}); }
  return result;
}

app.get('/api/status', requireUser, async (req, res) => {
  const { data } = await adminClient.from('scan_runs').select('*').eq('user_id', req.identity.user.id).order('created_at', { ascending: false }).limit(1).maybeSingle();
  if (!data) return res.json({ running: false, progress: 0, total: 0, current: '', log: [], counts: { mailboxes: 0, inputs: 0 }, results: null });
  res.json({ running: data.status === 'running' || data.status === 'stopping', mode: data.mode, started_at: data.started_at, finished_at: data.finished_at, progress: data.progress, total: data.total, current: data.current, log: data.log || [], counts: data.counts, results: data.results });
});

app.post('/api/start', requireUser, async (req, res) => {
  const mailboxes = String(req.body?.mailboxes || '').split('\n').map(parseMailboxLine).filter(Boolean);
  const inputs = String(req.body?.inputs || '').split('\n').map((value) => value.trim()).filter(Boolean);
  if (!mailboxes.length) return res.status(400).json({ error: 'No valid mailboxes provided' });
  if (!inputs.length) return res.status(400).json({ error: 'No search inputs provided' });
  const { data: previous } = await adminClient.from('scan_runs').select('id,status').eq('user_id', req.identity.user.id).in('status', ['running', 'stopping']).maybeSingle();
  if (previous) return res.status(400).json({ error: 'A scan is already running' });
  const { data: run, error } = await adminClient.from('scan_runs').insert({ user_id: req.identity.user.id, status: 'running', mode: req.body?.mode || 'hybrid', started_at: new Date().toISOString(), total: mailboxes.length, counts: { mailboxes: mailboxes.length, inputs: inputs.length }, log: ['Scan started'] }).select().single();
  if (error || !run) return res.status(500).json({ error: 'Could not start scan' });
  const runState = { progress: 0, current: 'Initializing', results: [], log: ['Scan started'] };
  runningRuns.set(run.id, runState);
  res.json({ status: 'started' });
  (async () => {
    for (const mailbox of mailboxes) {
      if (stopRequests.has(run.id)) break;
      const result = await scanMailbox(mailbox, inputs, run.id, runState);
      runState.results.push(result);
      runState.log.push(`${mailbox.email}: ${result.status}`);
      await adminClient.from('scan_runs').update({ progress: runState.results.length, current: runState.current, log: runState.log, results: { inputs: inputs.map((text, index) => ({ text, spam: runState.results.reduce((sum, item) => sum + item.spam[index], 0), inbox: runState.results.reduce((sum, item) => sum + item.inbox[index], 0), mailboxes: runState.results.map((item) => ({ email: item.email, status: item.status, error: item.error, inbox: item.inbox[index], spam: item.spam[index], previews: [...item.previews.inbox[index], ...item.previews.spam[index]] })) })), mailboxes: runState.results.map((item) => ({ email: item.email, status: item.status, error: item.error, inbox_total: item.inbox_total, spam_total: item.spam_total, folders: item.folders })) } }).eq('id', run.id);
    }
    await adminClient.from('scan_runs').update({ status: stopRequests.has(run.id) ? 'completed' : 'completed', finished_at: new Date().toISOString(), current: 'Finished', log: [...runState.log, 'Scan finished'] }).eq('id', run.id);
    stopRequests.delete(run.id); runningRuns.delete(run.id);
  })().catch(async () => { await adminClient.from('scan_runs').update({ status: 'failed', finished_at: new Date().toISOString(), log: [...runState.log, 'Scan failed'] }).eq('id', run.id); runningRuns.delete(run.id); });
});

app.post('/api/stop', requireUser, async (req, res) => {
  const { data: run } = await adminClient.from('scan_runs').select('id').eq('user_id', req.identity.user.id).in('status', ['running', 'stopping']).maybeSingle();
  if (run) { stopRequests.add(run.id); await adminClient.from('scan_runs').update({ status: 'stopping', log: ['Stop requested'] }).eq('id', run.id); }
  res.json({ status: 'stopping' });
});

app.post('/api/reset', requireUser, async (req, res) => {
  const { data: run } = await adminClient.from('scan_runs').select('id').eq('user_id', req.identity.user.id).order('created_at', { ascending: false }).limit(1).maybeSingle();
  if (run) await adminClient.from('scan_runs').update({ status: 'reset', results: null, current: 'Reset', log: ['System state reset'] }).eq('id', run.id);
  res.json({ status: 'reset' });
});

app.listen(port, '0.0.0.0', () => console.log(`Mailbox Hit Checker listening on ${port}`));
