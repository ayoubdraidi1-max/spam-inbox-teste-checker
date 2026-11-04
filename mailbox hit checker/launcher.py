#!/usr/bin/env python3
"""Tkinter launcher for the Mailbox Hit Checker app.

Buttons
  - Find free port : picks an available port
  - Install        : installs the Python dependencies (Flask)
  - Launch         : starts the Flask server on the selected port
  - Stop           : stops the running server
"""

import os
import queue
import shutil
import socket
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from tkinter import ttk

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
APP_ENTRY = os.path.join(PROJECT_DIR, "app.py")
REQUIREMENTS = os.path.join(PROJECT_DIR, "requirements.txt")

DEFAULT_PORT = 5010


def resolve_python():
    exe = sys.executable
    if exe and os.path.basename(exe).lower().startswith("python") and os.path.isfile(exe):
        return exe
    found = shutil.which("python") or shutil.which("py")
    return found or "python"


PYTHON_EXE = resolve_python()


def is_port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def find_free_port(preferred=DEFAULT_PORT, limit=300):
    if preferred and is_port_free(preferred):
        return preferred
    for port in range(preferred + 1, preferred + 1 + limit):
        if is_port_free(port):
            return port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class LauncherApp:
    def __init__(self, root):
        self.root = root
        self.server_proc = None
        self.log_queue = queue.Queue()

        root.title("Mailbox Hit Checker — Launcher")
        root.geometry("720x460")
        root.minsize(620, 400)

        self.port_var = tk.StringVar(value=str(find_free_port()))
        self.status_var = tk.StringVar(value="stopped")

        self._build_ui()
        self.root.after(120, self._drain_log_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.log("Python : " + PYTHON_EXE)
        self.log("App    : " + APP_ENTRY)
        self.log("Port   : " + self.port_var.get())

    # ---------------- UI ----------------
    def _build_ui(self):
        container = ttk.Frame(self.root, padding=12)
        container.pack(fill="both", expand=True)

        controls = ttk.Frame(container)
        controls.pack(fill="x")

        ttk.Label(controls, text="Port:").pack(side="left")
        ttk.Entry(controls, textvariable=self.port_var, width=8).pack(side="left", padx=(6, 10))
        ttk.Button(controls, text="Find free port", width=15, command=self._pick_free_port).pack(side="left")
        ttk.Button(controls, text="Install", width=10, command=self._install_deps).pack(side="left", padx=(10, 0))
        ttk.Button(controls, text="Launch", width=10, command=self._launch).pack(side="left", padx=(10, 0))
        ttk.Button(controls, text="Stop", width=10, command=self._stop).pack(side="left", padx=(10, 0))

        status_row = ttk.Frame(container)
        status_row.pack(fill="x", pady=(8, 6))
        ttk.Label(status_row, text="Status:").pack(side="left")
        ttk.Label(status_row, textvariable=self.status_var, foreground="#555").pack(side="left", padx=(6, 12))
        ttk.Button(status_row, text="Open in browser", command=self._open_browser).pack(side="left")
        ttk.Button(status_row, text="Clear log", command=self._clear_log).pack(side="left", padx=(10, 0))

        log_frame = ttk.LabelFrame(container, text="Console", padding=6)
        log_frame.pack(fill="both", expand=True)
        self.log_text = tk.Text(log_frame, height=14, wrap="none", bg="#111418", fg="#e6e6e6",
                                insertbackground="#e6e6e6", relief="flat")
        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    # ---------------- log ----------------
    def log(self, message):
        self.log_queue.put(str(message).rstrip("\n"))

    def _drain_log_queue(self):
        try:
            while True:
                line = self.log_queue.get_nowait()
                self.log_text.insert("end", line + "\n")
                self.log_text.see("end")
        except queue.Empty:
            pass
        self.root.after(120, self._drain_log_queue)

    def _clear_log(self):
        self.log_text.delete("1.0", "end")

    # ---------------- actions ----------------
    def _pick_free_port(self):
        port = find_free_port(DEFAULT_PORT)
        self.port_var.set(str(port))
        self.log("Free port found: %d" % port)

    def _validated_port(self):
        raw = self.port_var.get().strip()
        try:
            port = int(raw)
        except ValueError:
            self.log("Invalid port: %r" % raw)
            return None
        if not (1 <= port <= 65535):
            self.log("Port out of range: %d" % port)
            return None
        if not is_port_free(port):
            new_port = find_free_port(port)
            self.log("Port %d is busy -> switching to %d" % (port, new_port))
            self.port_var.set(str(new_port))
            return new_port
        return port

    def _install_deps(self):
        self._run([PYTHON_EXE, "-m", "pip", "install", "-r", REQUIREMENTS], "install")

    def _launch(self):
        if self._is_running():
            self.log("Server already running - stop it first.")
            return
        port = self._validated_port()
        if port is None:
            return
        self.log("Server will be available at http://127.0.0.1:%d" % port)

        def on_ready():
            webbrowser.open("http://127.0.0.1:%d" % port)

        self._run([PYTHON_EXE, APP_ENTRY, "--port", str(port)], "server", on_ready)

    def _stop(self):
        if not self._is_running():
            self.log("Server is not running.")
            return
        self.log("Stopping server pid %s ..." % self.server_proc.pid)
        try:
            self.server_proc.terminate()
        except Exception as exc:  # noqa: BLE001
            self.log("Stop error: %s" % exc)

    def _open_browser(self):
        url = "http://127.0.0.1:%s" % self.port_var.get().strip()
        self.log("Opening " + url)
        webbrowser.open(url)

    # ---------------- process handling ----------------
    def _is_running(self):
        return self.server_proc is not None and self.server_proc.poll() is None

    def _run(self, args, label, on_ready=None):
        self.log("[%s] $ %s" % (label, " ".join(args)))
        self.status_var.set("running: " + label)

        def worker():
            try:
                proc = subprocess.Popen(
                    args,
                    cwd=PROJECT_DIR,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    shell=False,
                )
            except Exception as exc:  # noqa: BLE001
                self.log("[%s] failed to start: %s" % (label, exc))
                self.status_var.set("stopped")
                return

            if label == "server":
                self.server_proc = proc
                if on_ready:
                    threading.Timer(1.8, on_ready).start()

            for line in proc.stdout:
                self.log("[%s] %s" % (label, line.rstrip("\n")))

            code = proc.wait()
            if label == "server":
                self.server_proc = None
            self.log("[%s] exited with code %s" % (label, code))
            self.status_var.set("stopped (exit %s)" % code)

        threading.Thread(target=worker, daemon=True).start()

    def _on_close(self):
        if self._is_running():
            self._stop()
        self.root.after(400, self.root.destroy)


def main():
    root = tk.Tk()
    LauncherApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
