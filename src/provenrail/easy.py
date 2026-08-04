"""The simple-to-the-max front door.

Everything Provenrail needs to do (provision a stream, mint tokens, build a recorder,
open a signed session, auto-instrument your model client, seal and drain on exit) collapses
into a single call:

    import provenrail as fr

    with fr.record("billing-agent"):
        ...   # your agent runs; model and tool calls are captured automatically

Connection details come from, in priority order: explicit arguments, a prior fr.configure(),
environment variables (PROVENRAIL_URL / _WRITE_TOKEN / _STREAM_ID / _ACCOUNT_KEY), then a
.provenrail.json file in the working directory or home directory (what `pr quickstart`
writes). So after one `pr quickstart`, user code carries no URLs or tokens at all.

Honesty note: this is a convenience wrapper, not a new trust model. The records still go to the
off-box sink and are still independently verifiable; nothing here weakens the guarantee.
"""

from __future__ import annotations

import functools
import json
import os
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

from .ingest_client import provision_stream
from .sdk import FlightRecorder

CONFIG_FILENAME = ".provenrail.json"
KEY_FILENAME = ".provenrail.key"

_GLOBAL: dict[str, Any] = {}

# The recorder for the currently-open record() session, so framework adapters
# (e.g. the LangChain ComplianceCallbackHandler) can find it without being passed it.
_ACTIVE: ContextVar[FlightRecorder | None] = ContextVar("provenrail_active_recorder", default=None)


def current_recorder() -> FlightRecorder | None:
    """Return the recorder for the innermost open record() session, or None."""
    return _ACTIVE.get()


def configure(*, endpoint: str | None = None, write_token: str | None = None,
              stream_id: str | None = None, account_key: str | None = None,
              http: Any | None = None, capture_content: bool | None = None) -> None:
    """Set process-wide defaults so later record() calls need no arguments."""
    for k, v in {"endpoint": endpoint, "write_token": write_token, "stream_id": stream_id,
                 "account_key": account_key, "http": http,
                 "capture_content": capture_content}.items():
        if v is not None:
            _GLOBAL[k] = v


def find_config_file(start: Path | None = None) -> Path | None:
    """Locate `.provenrail.json`, searching upward from `start` and then the home directory.

    Upward search is not a convenience here, it is a safety property. `pr guard install` writes
    the policy at the repo root, but an agent is routinely launched from a subdirectory (a
    package inside a monorepo, `apps/web`, a nested worktree). Looking only at the current
    directory means the guardrail silently finds no policy and allows everything, which is the
    worst possible failure mode: the user believes they are covered because they installed it.

    The walk stops at the filesystem root. Home stays the last resort so a machine-wide default
    still works when a project has no file of its own.
    """
    here = (start or Path.cwd()).resolve()
    for directory in (here, *here.parents):
        candidate = directory / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
    home = Path.home() / CONFIG_FILENAME
    return home if home.is_file() else None


def _load_config_file() -> dict[str, Any]:
    path = find_config_file()
    if path is None:
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _resolve(**overrides: Any) -> dict[str, Any]:
    """Merge connection settings: explicit args > configure() > env > config file."""
    file_cfg = _load_config_file()

    def _env(name: str) -> str | None:
        # Prefer the PROVENRAIL_* names; fall back to the legacy FLIGHTRECORDER_* names so an
        # already-configured environment keeps working after the rename.
        return os.environ.get(f"PROVENRAIL_{name}") or os.environ.get(f"FLIGHTRECORDER_{name}")

    env = {
        "endpoint": _env("URL"),
        "write_token": _env("WRITE_TOKEN"),
        "stream_id": _env("STREAM_ID"),
        "account_key": _env("ACCOUNT_KEY"),
    }
    out: dict[str, Any] = {}
    for key in ("endpoint", "write_token", "stream_id", "account_key", "http",
                "capture_content", "policy"):
        for source in (overrides, _GLOBAL, env, file_cfg):
            if source.get(key) is not None:
                out[key] = source[key]
                break
    return out


class PolicyConfigError(ValueError):
    """A policy in .provenrail.json is malformed.

    Raised loudly rather than ignored: a typo that silently disables a guardrail is the
    worst possible failure mode for this feature. An operator who thinks `delete_*` is
    blocked, and is wrong, is worse off than one who knows there is no policy at all.
    """


def load_policy(spec: Any) -> Any:
    """Build a Policy from a dict (as found under "policy" in .provenrail.json) or a path
    to a JSON file holding one. Returns None for None. Validates every rule."""
    from .policy import ALLOW, DENY, LIMIT, REQUIRE_OVERSIGHT, Policy, Rule

    if spec is None:
        return None
    if hasattr(spec, "decide"):     # already a Policy object
        return spec
    if isinstance(spec, (str, Path)):
        path = Path(spec)
        if not path.is_file():
            raise PolicyConfigError(f"policy file not found: {path}")
        try:
            spec = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as e:
            raise PolicyConfigError(f"policy file {path} is not valid JSON: {e}") from e
    if not isinstance(spec, dict):
        raise PolicyConfigError(f"policy must be an object or a path, got {type(spec).__name__}")

    valid_effects = {DENY, REQUIRE_OVERSIGHT, LIMIT, ALLOW}

    # "use" enables prebuilt rules from the catalogue by pack id or rule id. They are
    # prepended, so a custom rule with the same shape can still be added after, and an
    # unknown name raises rather than being skipped: a typo'd pack would otherwise leave
    # the operator believing a guardrail is on when nothing is.
    from . import rulesets
    use = spec.get("use")
    if use is not None and not isinstance(use, (list, tuple, str)):
        raise PolicyConfigError('policy "use" must be a list of pack or rule ids')
    try:
        prebuilt = rulesets.resolve(use)
    except rulesets.UnknownRuleError as e:
        raise PolicyConfigError(str(e)) from e

    rules = spec.get("rules", [])
    if not isinstance(rules, list):
        raise PolicyConfigError('policy "rules" must be a list')
    seen_ids = set()
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise PolicyConfigError(f"policy rule {i} must be an object")
        rid = rule.get("id")
        if not rid or not isinstance(rid, str):
            raise PolicyConfigError(f'policy rule {i} needs a string "id" (it names the rule '
                                    "in every recorded decision and alert)")
        if rid in seen_ids:
            raise PolicyConfigError(f'duplicate policy rule id "{rid}": ids must be unique so '
                                    "an alert names exactly one rule")
        seen_ids.add(rid)
        effect = rule.get("effect")
        if effect not in valid_effects:
            raise PolicyConfigError(
                f'policy rule "{rid}" has effect {effect!r}; expected one of '
                f"{sorted(valid_effects)}")
        if effect == LIMIT and not isinstance(rule.get("max_per_session"), int):
            raise PolicyConfigError(
                f'policy rule "{rid}" has effect "limit" but no integer "max_per_session", '
                "so it would never actually limit anything")
        if rule.get("arg_contains"):
            import re as _re
            try:
                _re.compile(rule["arg_contains"])
            except _re.error as e:
                raise PolicyConfigError(
                    f'policy rule "{rid}" has an invalid arg_contains regex: {e}') from e
        unknown = set(rule) - set(Rule._FIELDS)
        if unknown:
            raise PolicyConfigError(
                f'policy rule "{rid}" has unknown field(s) {sorted(unknown)}. A misspelled '
                "field would silently widen the rule, so it is rejected rather than ignored.")
    cap = spec.get("session_spend_cap_usd")
    if cap is not None:
        try:
            float(cap)
        except (TypeError, ValueError) as e:
            raise PolicyConfigError(
                f"session_spend_cap_usd must be a number, got {cap!r}") from e
    _validate_budgets(spec.get("budgets"), seen_ids)
    if prebuilt:
        # Catalogue rules are already validated by construction; user rules were validated
        # above. Custom rules come last so a user rule can shadow nothing by accident but
        # can always be added alongside.
        spec = {**spec, "rules": prebuilt + list(rules)}
        spec.pop("use", None)
    return Policy.from_dict(spec)


def write_config(path: str | Path, **cfg: Any) -> Path:
    """Persist a .provenrail.json so subsequent record() calls need zero arguments."""
    p = Path(path)
    p.write_text(json.dumps({k: v for k, v in cfg.items() if v is not None}, indent=2),
                 encoding="utf-8")
    return p


def _validate_budgets(budgets: Any, seen_ids: set[str]) -> None:
    """Reject a budget that cannot bind before it is trusted to.

    A misspelled scope or a missing limit would produce a config that reads like a spend
    control and enforces nothing, which is the single worst failure mode this feature has.
    """
    from .policy import BUDGET_SCOPES, Budget

    if budgets is None:
        return
    if not isinstance(budgets, list):
        raise PolicyConfigError('policy "budgets" must be a list')
    for i, budget in enumerate(budgets):
        if not isinstance(budget, dict):
            raise PolicyConfigError(f"policy budget {i} must be an object")
        unknown = set(budget) - set(Budget._FIELDS)
        if unknown:
            raise PolicyConfigError(
                f"policy budget {i} has unknown field(s) {sorted(unknown)}. A misspelled field "
                "would silently disable the cap, so it is rejected rather than ignored.")
        scope = budget.get("scope", "session")
        if scope not in BUDGET_SCOPES:
            raise PolicyConfigError(
                f"policy budget {i} has scope {scope!r}; expected one of {sorted(BUDGET_SCOPES)}")
        try:
            limit_usd = float(budget["limit_usd"])
        except (KeyError, TypeError, ValueError) as e:
            raise PolicyConfigError(
                f'policy budget {i} needs a numeric "limit_usd" (without one it would never '
                "cap anything)") from e
        if limit_usd <= 0:
            raise PolicyConfigError(
                f"policy budget {i} has limit_usd {limit_usd}; a cap must be greater than zero")
        if "warn_at" in budget:
            try:
                warn_at = float(budget["warn_at"])
            except (TypeError, ValueError) as e:
                raise PolicyConfigError(
                    f"policy budget {i} warn_at must be a number between 0 and 1") from e
            if not 0.0 <= warn_at <= 1.0:
                raise PolicyConfigError(
                    f"policy budget {i} warn_at is {warn_at}; it is a fraction of the limit and "
                    "must be between 0 and 1")
        bid = budget.get("id") or f"budget.{scope}"
        if bid in seen_ids:
            raise PolicyConfigError(f'duplicate policy id "{bid}": budget and rule ids share one '
                                    "namespace so an alert names exactly one control")
        seen_ids.add(bid)


def _auto_instrument(client: Any, fr: FlightRecorder) -> None:
    """Wrap a model client by detecting its library, so `clients=[...]` just works."""
    module = type(client).__module__.split(".")[0].lower()
    if module == "openai":
        from .integrations import instrument_openai
        instrument_openai(client, fr)
    elif module == "anthropic":
        from .integrations import instrument_anthropic
        instrument_anthropic(client, fr)
    elif hasattr(client, "call_tool"):
        # Best effort: an MCP client session exposes call_tool.
        from .integrations import instrument_mcp
        instrument_mcp(client, fr)
    else:
        # Silently doing nothing here is a trust trap: the user passed clients=[...] expecting
        # automatic capture, and would ship believing calls are recorded when none are. Warn
        # loudly instead, and name what we got so they can fix it (or record calls explicitly).
        import warnings
        warnings.warn(
            f"provenrail: client of type {type(client).__module__}.{type(client).__qualname__} "
            f"was not recognized (expected an OpenAI, Anthropic, or MCP client), so its calls "
            f"will NOT be captured automatically. Record them explicitly with "
            f"run.record_model_call(...), or remove it from clients=[...].",
            stacklevel=3,
        )


def _device_key() -> Any:
    """Load the persistent device signing key, creating it on first use.

    Lives beside the config (cwd, falling back to home), permissions 0600. Keep it out
    of version control; losing it only means future runs sign with a new identity."""
    from .keys import SigningKey
    for path in (Path.cwd() / KEY_FILENAME, Path.home() / KEY_FILENAME):
        if path.is_file():
            return SigningKey.load(path)
    key = SigningKey.generate()
    key.save(Path.cwd() / KEY_FILENAME)
    return key


def make_recorder(agent: str | None = None, *, policy: Any | None = None,
                  clients: list[Any] | None = None, **conn: Any) -> FlightRecorder:
    """Build a ready FlightRecorder, auto-provisioning a stream if no token is configured.

    Most users call record() instead; this is for when you want the recorder object directly."""
    cfg = _resolve(**conn)
    if policy is None:
        # A policy declared in .provenrail.json applies without any code change, so
        # guardrails can be configured by whoever owns the deployment rather than only by
        # whoever wrote the agent.
        policy = load_policy(cfg.get("policy"))
    else:
        policy = load_policy(policy)
    endpoint = cfg.get("endpoint")
    if not endpoint:
        raise RuntimeError(
            "no Provenrail endpoint configured. Run `pr quickstart`, set PROVENRAIL_URL, "
            "or pass endpoint=... / call provenrail.configure(endpoint=...).")
    http = cfg.get("http")
    write_token, stream_id = cfg.get("write_token"), cfg.get("stream_id")
    key = None
    if write_token and stream_id:
        # A pinned stream outlives this process, and the verifier treats a mid-stream
        # device-key change as tampering, so runs that share a stream must share a key.
        key = _device_key()
    else:
        prov = provision_stream(endpoint, label=agent, http=http, api_key=cfg.get("account_key"))
        write_token, stream_id = prov["write_token"], prov["stream_id"]
    fr = FlightRecorder(endpoint, write_token, stream_id, http=http, policy=policy, key=key,
                        capture_content=bool(cfg.get("capture_content", False)))
    for c in clients or []:
        _auto_instrument(c, fr)
    return fr


@contextmanager
def record(agent: str = "agent", *, meta: dict[str, Any] | None = None,
           clients: list[Any] | None = None, policy: Any | None = None, **conn: Any):
    """Open a recorded session in one line. Provisions, builds, sessions, seals, and drains.

    Yields the FlightRecorder so you can still call fr.record_decision(...) etc. inside."""
    fr = make_recorder(agent, policy=policy, clients=clients, **conn)
    session_meta = {"agent": agent, **(meta or {})}
    token = _ACTIVE.set(fr)
    try:
        with fr.session(session_meta):
            yield fr
    finally:
        _ACTIVE.reset(token)


def recorded(agent: str = "agent", **kw: Any):
    """Decorator form: wrap a whole function in a recorded session.

        @provenrail.recorded("nightly-job")
        def run(): ...
    """
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            with record(agent, **kw):
                return fn(*args, **kwargs)
        return wrapper
    return deco
