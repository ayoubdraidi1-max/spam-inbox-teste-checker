"""Headless end-to-end test for Super Turbo mode with per-command timing."""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import app as A  # noqa: E402

INPUTS_FILE = r"C:\Users\a.draidi.ILEADTRAFFIC\Desktop\input lines.txt"
MAILBOX_FILE = r"C:\Users\a.draidi.ILEADTRAFFIC\Desktop\mailbox teste.txt"

MAX_EMAILS = int(os.environ.get("MAX_EMAILS", "20"))
FIRST_EMAILS = int(os.environ.get("FIRST_EMAILS", "0"))
CONNS = int(os.environ.get("CONNS", "8"))
BATCH = int(os.environ.get("BATCH", "8"))
ONLY = os.environ.get("ONLY", "").strip()

TIMINGS = []
T_LOCK = threading.Lock()


def read_lines(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return [ln for ln in fh.read().splitlines() if ln.strip()]


def timed_conn(host, port, email, pw):
    import imaplib
    conn = imaplib.IMAP4_SSL(host, port)

    orig_uid = conn.uid

    def uid_wrapper(command, *args):
        start = time.time()
        try:
            return orig_uid(command, *args)
        finally:
            with T_LOCK:
                TIMINGS.append((command.upper() if isinstance(command, str) else str(command),
                                time.time() - start))

    conn.uid = uid_wrapper
    conn.login(email, pw)
    return conn


def main():
    raw_inputs = read_lines(INPUTS_FILE)
    creds = []
    for line in read_lines(MAILBOX_FILE):
        if ":" in line:
            e, p = line.split(":", 1)
            creds.append((e.strip(), p.strip()))
    if ONLY:
        creds = [c for c in creds if c[0] == ONLY]

    print("Inputs: %d" % len(raw_inputs), flush=True)
    prepared = [A.prepare_input(x) for x in raw_inputs]

    cfg = {
        "mode": "turbo", "isp": A.load_isp_config(), "max_emails": MAX_EMAILS,
        "first_emails": FIRST_EMAILS,
        "previews": 5, "batch": 3, "timeout": 90, "max_fast_len": 512, "threads": 5,
        "turbo_conns": CONNS, "turbo_batch": BATCH, "max_part_bytes": 0,
    }

    for email, pw in creds:
        print("\n=== %s (conns=%d batch=%d first=%d last=%d) ===" % (email, CONNS, BATCH, FIRST_EMAILS, MAX_EMAILS), flush=True)
        domain = email.split("@", 1)[-1].lower()
        host, port = A.get_imap_server(domain, cfg["isp"])
        import socket
        socket.setdefaulttimeout(cfg["timeout"])
        try:
            mail = timed_conn(host, port, email, pw)
        except Exception as exc:
            print("LOGIN FAILED: %s" % exc, flush=True)
            continue

        def make_conn():
            return timed_conn(host, port, email, pw)

        inbox, spam, folders = A.find_folders(mail)
        print("inbox=%s spam=%s" % (inbox, spam), flush=True)

        with T_LOCK:
            TIMINGS.clear()
        start = time.time()
        counts, previews, total = A.scan_folder(mail, inbox, prepared, cfg, None, make_conn)
        dur = time.time() - start
        print("  INBOX emails=%d hits=%d TIME=%.2fs (%.2f emails/s)"
              % (total, sum(counts), dur, (total / dur) if dur else 0), flush=True)
        with T_LOCK:
            calls = list(TIMINGS)
        by_cmd = {}
        for name, dt in calls:
            b = by_cmd.setdefault(name, [0, 0.0])
            b[0] += 1
            b[1] += dt
        print("  IMAP uid() calls: total=%d" % len(calls), flush=True)
        for name, (n, tot) in sorted(by_cmd.items(), key=lambda kv: -kv[1][1]):
            print("    %-16s n=%-4d total=%.2fs  avg=%.2fs" % (name, n, tot, tot / n), flush=True)
        try:
            mail.logout()
        except Exception:
            pass


if __name__ == "__main__":
    main()
