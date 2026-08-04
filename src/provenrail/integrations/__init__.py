"""Drop-in auto-instrumentation for popular model SDKs.

Wrap a client once and every model call is captured, no per-call code:

    from provenrail.integrations import instrument_openai
    instrument_openai(client, recorder)

These wrap a client *instance* (not global monkeypatching), so capture is explicit and
scoped. They never raise into the caller's path: a capture failure is swallowed so the
agent keeps working, and the gap is detectable later via the chain, not hidden.
"""

from .agno import async_provenrail_tool_hook, instrument_agno, provenrail_tool_hook
from .anthropic import instrument_anthropic
from .claude_sdk import make_post_tool_hook, make_pre_tool_hook, provenrail_hooks
from .hermes import make_post_tool_call, make_pre_tool_call, register_provenrail
from .langchain import ComplianceCallbackHandler, compliance_handler, provenrail_callback
from .mcp import instrument_mcp
from .openai import instrument_openai

__all__ = [
    "instrument_openai",
    "instrument_anthropic",
    "instrument_mcp",
    "instrument_agno",
    "register_provenrail",
    "provenrail_tool_hook",
    "async_provenrail_tool_hook",
    "ComplianceCallbackHandler",
    "compliance_handler",
    "provenrail_callback",
    "provenrail_hooks",
    "make_pre_tool_hook",
    "make_post_tool_hook",
    "make_pre_tool_call",
    "make_post_tool_call",
]
