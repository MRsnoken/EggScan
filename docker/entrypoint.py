import fcntl
import os
from pathlib import Path
import sys


def get_web_address():
    host = os.environ.get("EGGSCAN_WEB_HOST", "").strip() or "0.0.0.0"
    raw_port = os.environ.get("EGGSCAN_WEB_PORT", "").strip() or "5000"
    try:
        port = int(raw_port)
    except ValueError:
        raise ValueError("EGGSCAN_WEB_PORT must be between 1 and 65535") from None
    if not 1 <= port <= 65535:
        raise ValueError("EGGSCAN_WEB_PORT must be between 1 and 65535")
    return host, port


def main():
    os.umask(0o077)
    source_dir = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(source_dir))
    arguments = sys.argv[1:] or ["web"]
    if arguments == ["web"]:
        host, port = get_web_address()
        bind_host = f"[{host}]" if ":" in host else host
        arguments = [
            "gunicorn", "--workers", "2", "--threads", "2",
            "--chdir", str(source_dir),
            "--bind", f"{bind_host}:{port}",
            "--access-logfile", "-", "--error-logfile", "-",
            "--worker-tmp-dir", "/tmp", "eggscan:app",
        ]
    elif arguments == ["scan-worker"]:
        arguments = [sys.executable, str(source_dir / "eggscan.py"), "scan-worker"]

    data_dir = Path(os.environ.get("EGGSCAN_DATA_DIR") or "/data").resolve()
    os.environ["EGGSCAN_DATA_DIR"] = str(data_dir)
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    with (data_dir / ".startup.lock").open("a") as startup_lock:
        fcntl.flock(startup_lock, fcntl.LOCK_EX)
        import eggscan

        with eggscan.app.app_context():
            eggscan.db.session.remove()
            eggscan.db.engine.dispose()

    os.execvp(arguments[0], arguments)


if __name__ == "__main__":
    main()
