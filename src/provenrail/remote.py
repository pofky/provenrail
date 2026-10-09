"""The phone remote: approve, refuse and stop your agents when you are not at the keyboard.

A rule that says "ask a human" is only as good as the human's ability to answer. At the
keyboard, the host's own prompt does that. Away from it, the agent waits for hours, or the
host has no prompt at all and the rule can only refuse. This module carries the question to
a phone and the answer back.

**There is no Provenrail server in this.** The message goes from this machine to a channel
the user already controls, and the answer comes back the same way:

* **Telegram**, through a bot the user creates. Answers are accepted only from the one chat
  that was paired by typing a code this machine printed.
* **ntfy**, through a topic on ntfy.sh or a self-hosted server. The topic name is the secret:
  anyone who knows it can answer, so it is 128 random bits and never printed after setup.

Either way the text of the question (the rule, the tool, and by default the command) leaves
the machine and passes through that service. That is the user's decision, made at
`pr remote setup`, and `"detail": "shape"` reduces what is sent to the verb and its flags.

It never fails open. No answer, a network error, an unpaired chat, an expired evaluation:
every one of them leaves the verdict exactly what it was before the remote was consulted.

Standard library only, Python 3.9 compatible: vendored into the zero-install plugin.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
from typing import Any
from urllib.parse import quote as _quote

try:                                  # installed as part of the package
    from . import localstate, watch
except ImportError:                   # vendored: the hook imports it as a top-level module
    import localstate  # type: ignore[no-redef]
    import watch  # type: ignore[no-redef]

CONFIG_FILENAME = "remote.json"
STATE_FILENAME = "remote-state.json"
LOCK_FILENAME = "remote.lock"
AWAY_FILENAME = "away"

TELEGRAM_API = "https://api.telegram.org"
NTFY_DEFAULT_SERVER = "https://ntfy.sh"

#: Seconds a question waits for an answer by default. Five minutes is long enough to take a
#: phone out and read a command, and short enough that an unanswered question falls back to
#: the host's own behaviour before the session's prompt cache has gone cold twice over.
DEFAULT_WAIT_S = 300
#: The longest wait a config may ask for. The hook's own timeout is set just above this by
#: `HOOK_TIMEOUT_S`, and a wait past the hook timeout would be killed by the host mid-question,
#: which the host treats as "no opinion": an approval prompt that silently becomes an allow.
MAX_WAIT_S = 600
#: What the installed hook's timeout must be for a wait of `MAX_WAIT_S` to finish inside it.
HOOK_TIMEOUT_S = MAX_WAIT_S + 30

#: One long-poll slice while waiting. Short, so the lock other waiting hooks need is released
#: often and two questions in flight both get their answers.
_SLICE_S = 5
_HTTP_TIMEOUT_S = 10

#: Minimum seconds between background checks for a `stop` sent from the phone. This bounds
#: how stale a stop can be: the order takes effect on the first tool call after the check.
POLL_INTERVAL_S = 20

#: Days the remote works without a licence, counted from `pr remote setup`.
TRIAL_DAYS = 14

#: Seconds without keyboard or pointer input after which the user is taken to be away. Two
#: minutes is past any pause to read output and well short of a coffee. Only macOS exposes
#: this without extra software; elsewhere `pr away` says it explicitly.
IDLE_AWAY_S = 120

#: Characters of the command sent with a question. Telegram's own limit is 4096 per message;
#: 600 shows a long command whole on a phone screen without scrolling past the buttons.
MAX_BODY_CHARS = 600

_ANSWER_TTL_S = 24 * 3600
_COMMANDS = ("stop", "resume", "away", "back", "status")


class RemoteError(RuntimeError):
    """The channel could not be used. The message never contains a token or a topic."""


# ---------------------------------------------------------------- config and state


def config_file():
    return localstate.home() / CONFIG_FILENAME


def load() -> dict[str, Any] | None:
    cfg = localstate.read_json(config_file(), None)
    if not isinstance(cfg, dict):
        return None
    if cfg.get("provider") == "telegram" and cfg.get("token") and cfg.get("chat_id"):
        return cfg
    if cfg.get("provider") == "ntfy" and cfg.get("topic"):
        return cfg
    return None


def save(cfg: dict[str, Any]) -> None:
    path = config_file()
    localstate.write_json(path, cfg)
    try:
        os.chmod(path, 0o600)            # it holds a bot token or a topic that is a password
    except OSError:
        pass


def forget() -> bool:
    removed = False
    for name in (CONFIG_FILENAME, STATE_FILENAME):
        try:
            (localstate.home() / name).unlink()
            removed = True
        except OSError:
            pass
    return removed


def _state() -> dict[str, Any]:
    data = localstate.read_json(localstate.home() / STATE_FILENAME, {})
    return data if isinstance(data, dict) else {}


def _save_state(state: dict[str, Any]) -> None:
    localstate.write_json(localstate.home() / STATE_FILENAME, state)


def entitled(cfg: dict[str, Any], licensed: Any, now: float | None = None) -> tuple:
    """(usable, note). `licensed` is True, False, or None when this engine cannot check one.

    A commercial control and not a security one, exactly like the licence it reads: the code
    is open and the check can be edited out. What it must never do is weaken a verdict, so an
    expired evaluation means the remote is simply not consulted.
    """
    if licensed is True:
        return True, ""
    stamp = time.time() if now is None else now
    started = float(cfg.get("installed_at") or 0)
    left = TRIAL_DAYS - int((stamp - started) // 86400)
    if started and left > 0:
        return True, f"evaluation, {left} day{'s' if left != 1 else ''} left"
    how = ("run `pr activate <key>`" if licensed is False else
           "install the CLI (`uv tool install provenrail`) and run `pr activate <key>`")
    return False, (f"the {TRIAL_DAYS}-day evaluation of the phone remote has ended, so "
                   f"questions are staying on this machine. To keep it, {how}. "
                   "https://provenrail.com/pricing")


# ---------------------------------------------------------------- away


def set_away(value: bool) -> None:
    path = localstate.home() / AWAY_FILENAME
    if value:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(int(time.time())), encoding="utf-8")
    else:
        try:
            path.unlink()
        except OSError:
            pass


def idle_seconds() -> float | None:
    """Seconds since the last keyboard or pointer input, or None when it cannot be known."""
    if sys.platform != "darwin":
        return None
    try:
        out = subprocess.run(["ioreg", "-c", "IOHIDSystem", "-d", "4"], capture_output=True,
                             text=True, timeout=2, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        if "HIDIdleTime" in line:
            try:
                return int(line.rsplit("=", 1)[1].strip()) / 1e9
            except (ValueError, IndexError):
                return None
    return None


def is_away() -> bool:
    if os.environ.get("PROVENRAIL_AWAY") == "1" or (localstate.home() / AWAY_FILENAME).exists():
        return True
    idle = idle_seconds()
    return idle is not None and idle >= IDLE_AWAY_S


def wants_remote(cfg: dict[str, Any], host_can_ask: bool) -> bool:
    """Whether this question should go to the phone rather than to the host's own prompt.

    A hook cannot show the host's prompt and wait on a phone at once: it has to choose. A
    host that cannot ask at all always goes to the phone, because the alternative is a flat
    refusal. A host that can ask goes to the phone only when the user is away, since sending
    someone to their phone for a question on the screen in front of them is how a feature
    gets switched off.
    """
    mode = cfg.get("ask") or "auto"
    if mode == "never":
        return False
    if mode == "always" or not host_can_ask:
        return True
    return is_away()


# ---------------------------------------------------------------- transport


def _scrub(text: str, cfg: dict[str, Any] | None) -> str:
    for secret in ((cfg or {}).get("token"), (cfg or {}).get("topic")):
        if secret:
            text = text.replace(str(secret), "[redacted]")
    return text


def _http(method: str, url: str, body: Any = None, timeout: float = _HTTP_TIMEOUT_S) -> bytes:
    """One request. Tests replace this function; nothing else in the module opens a socket."""
    if not url.startswith(("https://", "http://")):
        raise RemoteError("the remote only speaks http and https")
    data = None
    headers = {"User-Agent": "provenrail-remote"}
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        if not isinstance(body, bytes):
            headers["Content-Type"] = "application/json"
    # Imported here, not at the top: this module is loaded on every tool call an agent makes
    # and the HTTP stack costs tens of milliseconds to import, for a socket that almost no
    # call ever opens.
    import urllib.request
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return response.read()


def _call(cfg: dict[str, Any], method: str, url: str, body: Any = None,
          timeout: float = _HTTP_TIMEOUT_S) -> bytes:
    try:
        return _http(method, url, body, timeout)
    except RemoteError:
        raise
    except Exception as exc:  # noqa: BLE001 - a hook must survive anything a socket can throw
        code = getattr(exc, "code", None)            # urllib.error.HTTPError, without the import
        if isinstance(code, int):
            raise RemoteError(f"the {cfg.get('provider')} service answered HTTP {code}") from None
        raise RemoteError(_scrub(f"could not reach {cfg.get('provider')} "
                                 f"({type(exc).__name__})", cfg)) from None


def _telegram(cfg: dict[str, Any], method: str, payload: dict[str, Any],
              timeout: float = _HTTP_TIMEOUT_S) -> Any:
    raw = _call(cfg, "POST", f"{TELEGRAM_API}/bot{cfg['token']}/{method}", payload, timeout)
    try:
        data = json.loads(raw)
    except ValueError:
        raise RemoteError("telegram sent something that is not JSON") from None
    if not isinstance(data, dict) or not data.get("ok"):
        raise RemoteError("telegram refused the request")
    return data.get("result")


def _ntfy_server(cfg: dict[str, Any]) -> str:
    return str(cfg.get("server") or NTFY_DEFAULT_SERVER).rstrip("/")


def _reply_topic(cfg: dict[str, Any]) -> str:
    return f"{cfg['topic']}-r"


def send(cfg: dict[str, Any], title: str, body: str, request_id: str = "") -> None:
    """Deliver one message, with Approve and Deny buttons when `request_id` is given."""
    body = body[:MAX_BODY_CHARS + 200]
    if cfg["provider"] == "telegram":
        payload: dict[str, Any] = {"chat_id": cfg["chat_id"], "text": f"{title}\n\n{body}",
                                   "disable_web_page_preview": True}
        if request_id:
            payload["reply_markup"] = {"inline_keyboard": [[
                {"text": "Approve", "callback_data": f"a:{request_id}"},
                {"text": "Deny", "callback_data": f"d:{request_id}"}]]}
        _telegram(cfg, "sendMessage", payload)
        return
    server = _ntfy_server(cfg)
    payload = {"topic": cfg["topic"], "title": title, "message": body or title}
    if request_id:
        reply = f"{server}/{_quote(_reply_topic(cfg))}"
        payload["priority"] = 4
        payload["actions"] = [
            {"action": "http", "label": "Approve", "url": reply, "method": "POST",
             "body": f"a:{request_id}", "clear": True},
            {"action": "http", "label": "Deny", "url": reply, "method": "POST",
             "body": f"d:{request_id}", "clear": True}]
    _call(cfg, "POST", server + "/", payload)


def _absorb(state: dict[str, Any], text: str, now: float) -> None:
    """File one piece of incoming text as an answer or a command. Anything else is dropped."""
    text = (text or "").strip()
    if len(text) > 2 and text[1] == ":" and text[0] in "ad":
        state.setdefault("inbox", {})[text[2:66]] = {
            "answer": "approve" if text[0] == "a" else "deny", "at": int(now)}
        return
    word = text.lstrip("/").split("@", 1)[0].split(" ", 1)[0].lower()
    if word in _COMMANDS:
        state.setdefault("commands", []).append(word)


def fetch(cfg: dict[str, Any], wait_s: float = 0, now: float | None = None) -> None:
    """Pull whatever has arrived into the shared state: answers into the inbox, and the
    words `stop`, `resume`, `away`, `back`, `status` into the command queue.

    Under one lock, because Telegram hands each update to exactly one caller. Two hooks
    waiting on two questions would otherwise each consume the other's answer and both time
    out. Whoever holds the lock files every answer it receives, for whoever is waiting.
    """
    stamp = time.time() if now is None else now
    with localstate.locked(localstate.home() / LOCK_FILENAME):
        state = _state()
        if cfg["provider"] == "telegram":
            updates = _telegram(cfg, "getUpdates", {
                "offset": int(state.get("offset") or 0), "timeout": int(wait_s),
                "allowed_updates": ["callback_query", "message"]},
                timeout=wait_s + _HTTP_TIMEOUT_S)
            for update in updates if isinstance(updates, list) else []:
                if not isinstance(update, dict):
                    continue
                state["offset"] = max(int(state.get("offset") or 0),
                                      int(update.get("update_id") or 0) + 1)
                query = update.get("callback_query")
                message = update.get("message")
                if isinstance(query, dict):
                    chat = ((query.get("message") or {}).get("chat") or {}).get("id")
                    # Only the paired chat may answer. A bot is reachable by anyone who
                    # finds its name, and an approval from a stranger is not an approval.
                    if chat == cfg["chat_id"]:
                        _absorb(state, str(query.get("data") or ""), stamp)
                    try:
                        _telegram(cfg, "answerCallbackQuery",
                                  {"callback_query_id": query.get("id")})
                    except RemoteError:
                        pass
                elif isinstance(message, dict):
                    if (message.get("chat") or {}).get("id") == cfg["chat_id"]:
                        _absorb(state, str(message.get("text") or ""), stamp)
        else:
            since = state.get("since") or str(int(float(cfg.get("installed_at") or stamp)))
            url = (f"{_ntfy_server(cfg)}/{_quote(_reply_topic(cfg))}/json"
                   f"?poll=1&since={_quote(str(since))}")
            raw = _call(cfg, "GET", url)
            for line in raw.splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if isinstance(event, dict) and event.get("event") == "message":
                    state["since"] = str(event.get("id") or state.get("since") or since)
                    _absorb(state, str(event.get("message") or ""), stamp)
            if wait_s:
                time.sleep(min(wait_s, 2))       # ntfy's poll returns at once; pace the loop
        inbox = state.get("inbox") or {}
        state["inbox"] = {rid: note for rid, note in inbox.items()
                          if stamp - float(note.get("at") or 0) < _ANSWER_TTL_S}
        state["polled_at"] = int(stamp)
        _save_state(state)


def _take_answer(request_id: str) -> str:
    with localstate.locked(localstate.home() / LOCK_FILENAME):
        state = _state()
        note = (state.get("inbox") or {}).pop(request_id, None)
        if note is None:
            return ""
        _save_state(state)
        return str(note.get("answer") or "")


def ask(cfg: dict[str, Any], title: str, body: str, wait_s: float = DEFAULT_WAIT_S) -> str:
    """Put a question to the phone. Returns "approve", "deny", "timeout" or "error"."""
    wait_s = max(1.0, min(float(wait_s), float(MAX_WAIT_S)))
    request_id = secrets.token_hex(8)
    try:
        send(cfg, title, body, request_id)
    except RemoteError:
        return "error"
    deadline = time.monotonic() + wait_s
    failures = 0
    while True:
        answer = _take_answer(request_id)
        if answer:
            return answer
        left = deadline - time.monotonic()
        if left <= 0:
            return "timeout"
        try:
            fetch(cfg, wait_s=min(_SLICE_S, max(0.0, left)))
            failures = 0
            # A `stop` sent while a question is open is an answer to it, and the clearest
            # one there is.
            if "stop" in apply_commands(cfg):
                return "deny"
        except RemoteError:
            failures += 1
            if failures >= 3:
                return "error"
            time.sleep(min(2.0, max(0.0, left)))


def notify(cfg: dict[str, Any], title: str, body: str) -> bool:
    try:
        send(cfg, title, body)
        return True
    except RemoteError:
        return False


# ---------------------------------------------------------------- commands from the phone


def apply_commands(cfg: dict[str, Any]) -> list[str]:
    """Carry out queued commands and confirm each one back to the phone."""
    with localstate.locked(localstate.home() / LOCK_FILENAME):
        state = _state()
        commands = [c for c in state.get("commands") or [] if c in _COMMANDS]
        if commands:
            state["commands"] = []
            _save_state(state)
    for command in commands:
        if command == "stop":
            watch.halt(by="the phone remote")
            notify(cfg, "Stopped", "Every agent on this machine is refused from its next "
                                   "tool call. Send resume to let them continue.")
        elif command == "resume":
            watch.resume()
            notify(cfg, "Resumed", "Agents on this machine may run again.")
        elif command == "away":
            set_away(True)
            notify(cfg, "Away", "Questions will come here until you send back.")
        elif command == "back":
            set_away(False)
            notify(cfg, "Back", "Questions will be asked at the machine while you are at it.")
        elif command == "status":
            order = watch.halted()
            notify(cfg, "Status", ("STOPPED. " + watch.halt_reason(order)) if order else
                   ("Running. " + ("Away: questions come here." if is_away() else
                                   "Questions are asked at the machine.")))
    return commands


def poll_due(now: float | None = None) -> bool:
    stamp = time.time() if now is None else now
    return stamp - float(_state().get("polled_at") or 0) >= POLL_INTERVAL_S


def poll_in_background() -> bool:
    """Check for a `stop` from the phone without making this tool call wait for the network.

    Spawned detached and at most once per `POLL_INTERVAL_S`. The result lands in the stop
    file, which the NEXT tool call reads; this one has already been decided.
    """
    if not poll_due():
        return False
    # Stamp before spawning, so a burst of tool calls starts one poller and not forty.
    with localstate.locked(localstate.home() / LOCK_FILENAME):
        state = _state()
        state["polled_at"] = int(time.time())
        _save_state(state)
    command = ([sys.executable, "-m", "provenrail.remote", "--poll"] if __package__
               else [sys.executable, os.path.abspath(__file__), "--poll"])
    try:
        subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
        return True
    except OSError:
        return False


def poll_once() -> list[str]:
    cfg = load()
    if cfg is None:
        return []
    try:
        fetch(cfg)
    except RemoteError:
        return []
    return apply_commands(cfg)


# ---------------------------------------------------------------- command line


def _setup_telegram(args: Any, out: Any) -> int:
    token = (args.token or os.environ.get("PROVENRAIL_TELEGRAM_TOKEN") or "").strip()
    if not token:
        out.write("Create a bot first: message @BotFather on Telegram, send /newbot, and it "
                  "gives you a token.\nThen: pr remote setup telegram --token <token>\n")
        return 2
    cfg: dict[str, Any] = {"provider": "telegram", "token": token, "chat_id": 0,
                           "installed_at": int(time.time())}
    try:
        me = _telegram(cfg, "getMe", {})
    except RemoteError as exc:
        out.write(f"pr remote: {exc}. Check the token.\n")
        return 1
    code = f"{secrets.randbelow(900000) + 100000}"
    out.write(f"Open https://t.me/{(me or {}).get('username', '')} and send it this code "
              f"within {args.wait} seconds:\n\n    {code}\n\n")
    out.flush()
    deadline = time.monotonic() + args.wait
    offset = 0
    while time.monotonic() < deadline:
        try:
            updates = _telegram(cfg, "getUpdates", {"offset": offset, "timeout": _SLICE_S,
                                                    "allowed_updates": ["message"]},
                                timeout=_SLICE_S + _HTTP_TIMEOUT_S)
        except RemoteError as exc:
            out.write(f"pr remote: {exc}\n")
            return 1
        for update in updates or []:
            offset = max(offset, int(update.get("update_id") or 0) + 1)
            message = update.get("message") or {}
            # Paired by the code, not by whoever messages the bot first: a bot's name is
            # public, and the first message could be anyone's.
            if str(message.get("text") or "").strip() == code:
                cfg["chat_id"] = (message.get("chat") or {}).get("id")
                save(cfg)
                _save_state({"offset": offset})
                notify(cfg, "Provenrail remote is paired",
                       "Questions from your agents will arrive here with Approve and Deny. "
                       "Send stop to halt every agent on that machine, resume to continue, "
                       "away or back to say where questions should go.")
                out.write("Paired. `pr remote test` sends a question you can answer.\n")
                return 0
    out.write("No message with that code arrived, so nothing was saved. Run it again.\n")
    return 1


def _setup_ntfy(args: Any, out: Any) -> int:
    cfg: dict[str, Any] = {"provider": "ntfy", "topic": "pr-" + secrets.token_hex(16),
                           "installed_at": int(time.time())}
    if args.server:
        cfg["server"] = args.server.rstrip("/")
    out.write(f"In the ntfy app, subscribe to this topic on {_ntfy_server(cfg)}:\n\n"
              f"    {cfg['topic']}\n\nIt is a password: anyone who knows it can answer for "
              f"you. Then tap Approve on the message that arrives (within {args.wait} "
              "seconds).\n")
    out.flush()
    time.sleep(0 if args.wait <= 5 else 8)       # time to type the topic before the message
    answer = ask(cfg, "Provenrail remote", "Tap Approve to finish pairing this machine.",
                 wait_s=args.wait)
    if answer != "approve":
        out.write(f"Not confirmed ({answer}), so nothing was saved. Run it again.\n")
        return 1
    save(cfg)
    out.write("Paired. `pr remote test` sends a question you can answer.\n")
    return 0


def add_arguments(parser: Any) -> None:
    parser.add_argument("action", nargs="?", default="status",
                        choices=["setup", "test", "status", "off"])
    parser.add_argument("provider", nargs="?", default="", choices=["", "telegram", "ntfy"])
    parser.add_argument("--token", default="", help="telegram bot token from @BotFather")
    parser.add_argument("--server", default="", help="ntfy server (default https://ntfy.sh)")
    parser.add_argument("--wait", type=int, default=120, help="seconds to wait for the phone")


def run(args: Any, licensed: Any = None, out: Any = None) -> int:
    out = out or sys.stdout
    if args.action == "setup":
        if args.provider == "telegram":
            return _setup_telegram(args, out)
        if args.provider == "ntfy":
            return _setup_ntfy(args, out)
        out.write("pr remote setup telegram --token <token>   a bot you create, most private\n"
                  "pr remote setup ntfy                       no account, a secret topic\n")
        return 2
    cfg = load()
    if args.action == "off":
        out.write("Remote removed from this machine.\n" if forget() else
                  "No remote was set up.\n")
        return 0
    if cfg is None:
        out.write("No phone remote is set up. `pr remote setup` shows the two ways.\n")
        return 0 if args.action == "status" else 1
    usable, note = entitled(cfg, licensed)
    if args.action == "status":
        out.write(f"Remote: {cfg['provider']}"
                  + (f" ({note})" if usable and note else "")
                  + ("" if usable else f"\nNOT in use: {note}") + "\n"
                  f"Questions go to the phone: {cfg.get('ask') or 'auto'} "
                  f"(right now: {'phone' if is_away() else 'this machine, you are at it'})\n")
        order = watch.halted()
        out.write(("STOPPED: " + watch.halt_reason(order) + "\n") if order else
                  "Agents are free to run. `pr stop` halts all of them.\n")
        return 0
    if not usable:
        out.write(note + "\n")
        return 1
    out.write(f"Sent a test question. Waiting up to {args.wait} seconds for your answer.\n")
    out.flush()
    answer = ask(cfg, "Provenrail test question", "Approve or Deny. Nothing depends on it.",
                 wait_s=args.wait)
    out.write(f"Answer: {answer}\n")
    return 0 if answer in ("approve", "deny") else 1


if __name__ == "__main__":             # the detached poller: `python remote.py --poll`
    if "--poll" in sys.argv:
        poll_once()
