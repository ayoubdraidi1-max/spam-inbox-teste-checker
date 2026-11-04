import { createClient } from "npm:@supabase/supabase-js@2.49.1";
import { ImapFlow } from "npm:imapflow@1.0.181";
import { simpleParser } from "npm:mailparser@3.7.2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

const supabaseUrl = Deno.env.get("SUPABASE_URL");
const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

const adminClient = createClient(supabaseUrl, serviceRoleKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

async function getCallerProfile(req) {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader) return null;
  const token = authHeader.replace("Bearer ", "");
  const { data: userData, error } = await adminClient.auth.getUser(token);
  if (error || !userData.user) return null;
  const { data: profile } = await adminClient
    .from("profiles")
    .select("id,email,role")
    .eq("id", userData.user.id)
    .maybeSingle();
  return profile;
}

function parseMailboxLine(line) {
  const sep = line.indexOf(":");
  if (sep <= 0) return null;
  return { email: line.slice(0, sep).trim(), password: line.slice(sep + 1).trim() };
}

function hostForEmail(email) {
  const domain = (email.split("@")[1] || "").toLowerCase();
  const hosts = {
    "gmail.com": "imap.gmail.com",
    "googlemail.com": "imap.gmail.com",
    "outlook.com": "outlook.office365.com",
    "hotmail.com": "outlook.office365.com",
    "live.com": "outlook.office365.com",
    "msn.com": "outlook.office365.com",
    "yahoo.com": "imap.mail.yahoo.com",
    "ymail.com": "imap.mail.yahoo.com",
    "aol.com": "imap.aol.com",
    "icloud.com": "imap.mail.me.com",
    "me.com": "imap.mail.me.com",
    "gmx.com": "imap.gmx.com",
    "gmx.net": "imap.gmx.net",
    "web.de": "imap.web.de",
    "zoho.com": "imap.zoho.com",
    "yandex.com": "imap.yandex.com",
  };
  return hosts[domain] || `imap.${domain}`;
}

async function scanMailbox(mailbox, inputs, maxEmails) {
  const result = {
    email: mailbox.email,
    status: "running",
    error: null,
    folders: {},
    inbox: inputs.map(() => 0),
    spam: inputs.map(() => 0),
    previews: { inbox: inputs.map(() => []), spam: inputs.map(() => []) },
    inbox_total: 0,
    spam_total: 0,
  };

  const client = new ImapFlow({
    host: hostForEmail(mailbox.email),
    port: 993,
    secure: true,
    auth: { user: mailbox.email, pass: mailbox.password },
    logger: false,
  });

  try {
    await client.connect();
    const listed = await client.list();
    const folderPaths = listed
      .filter((f) => /inbox|spam|junk/i.test(f.path))
      .map((f) => f.path);

    for (const folderPath of folderPaths) {
      const bucket = /spam|junk/i.test(folderPath) ? "spam" : "inbox";
      const lock = await client.getMailboxLock(folderPath);
      try {
        const uids = await client.search({ all: true });
        const uidList = maxEmails > 0 ? uids.slice(-maxEmails) : uids;

        for (const uid of uidList) {
          const msg = await client.fetchOne(uid, { source: true, envelope: true });
          if (!msg) continue;
          const parsed = await simpleParser(msg.source);
          const haystack = `${parsed.subject || ""}\n${parsed.from?.text || ""}\n${parsed.text || ""}`.toLowerCase();
          const preview = {
            subject: parsed.subject || "(no subject)",
            from: parsed.from?.text || "",
            date: parsed.date?.toISOString() || "",
            folder: bucket,
            snippet: (parsed.text || "").slice(0, 200),
          };

          for (let i = 0; i < inputs.length; i++) {
            if (haystack.includes(inputs[i].toLowerCase())) {
              result[bucket][i] += 1;
              if (result.previews[bucket][i].length < 5) {
                result.previews[bucket][i].push(preview);
              }
            }
          }
          result[`${bucket}_total`] += 1;
        }
      } finally {
        lock.release();
      }
    }
    result.status = "ok";
  } catch (err) {
    result.status = "error";
    result.error = err.message || "Mailbox connection failed";
  } finally {
    await client.logout().catch(() => {});
  }
  return result;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
  const profile = await getCallerProfile(req);
  if (!profile) return json({ error: "Not signed in" }, 401);

  const body = await req.json();
  const mailboxes = String(body.mailboxes || "")
    .split("\n")
    .map(parseMailboxLine)
    .filter(Boolean);
  const inputs = String(body.inputs || "")
    .split("\n")
    .map((v) => v.trim())
    .filter(Boolean);

  if (!mailboxes.length) return json({ error: "No valid mailboxes provided" }, 400);
  if (!inputs.length) return json({ error: "No search inputs provided" }, 400);

  const maxEmails = Number(body.max_emails) || 0;
  const mode = body.mode || "hybrid";

  const { data: run, error: runError } = await adminClient
    .from("scan_runs")
    .insert({
      user_id: profile.id,
      status: "running",
      mode,
      started_at: new Date().toISOString(),
      total: mailboxes.length,
      counts: { mailboxes: mailboxes.length, inputs: inputs.length },
      log: ["Scan started"],
    })
    .select()
    .single();

  if (runError || !run) return json({ error: "Could not start scan" }, 500);

  const runState = { progress: 0, log: ["Scan started"] };

  // Scan synchronously and return results when done
  const allResults = [];
  for (const mailbox of mailboxes) {
    const result = await scanMailbox(mailbox, inputs, maxEmails);
    allResults.push(result);
    runState.progress += 1;
    runState.log.push(`${mailbox.email}: ${result.status}`);
    await adminClient
      .from("scan_runs")
      .update({ progress: runState.progress, log: runState.log })
      .eq("id", run.id);
  }

  const resultsPayload = {
    mode,
    generated_at: new Date().toISOString(),
    inputs: inputs.map((text, i) => ({
      text: text.length > 800 ? text.slice(0, 800) + "..." : text,
      full_text_len: text.length,
      spam: allResults.reduce((s, m) => s + m.spam[i], 0),
      inbox: allResults.reduce((s, m) => s + m.inbox[i], 0),
      mailboxes: allResults.map((m) => ({
        email: m.email,
        status: m.status,
        error: m.error,
        inbox: m.inbox[i],
        spam: m.spam[i],
        previews: [...m.previews.inbox[i], ...m.previews.spam[i]],
      })),
    })),
    mailboxes: allResults.map((m) => ({
      email: m.email,
      status: m.status,
      error: m.error,
      inbox_total: m.inbox_total,
      spam_total: m.spam_total,
      folders: m.folders,
    })),
  };

  await adminClient
    .from("scan_runs")
    .update({
      status: "completed",
      finished_at: new Date().toISOString(),
      current: "Finished",
      log: [...runState.log, "Scan finished"],
      results: resultsPayload,
    })
    .eq("id", run.id);

  return json({ status: "completed", results: resultsPayload, run_id: run.id });
  } catch (err) {
    return json({ error: "Scan failed" }, 500);
  }
});
