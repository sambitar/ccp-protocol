"""Transport-neutral MCP bridge for CCP capabilities.

The bridge maps granted intents to MCP tools, signs a fresh signal per call,
and lets the runtime decide. It never approves a confirmation on the model's
behalf. Results are plain dataclasses so this module does not depend on an
MCP SDK; adapt them at the transport edge.
"""

import inspect
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ..consumer import PermissionCard, permission_card
from ..decision import confirmation_policy
from ..errors import AUTHORIZED, CONFIRMATION_REQUIRED, ERROR_CODES


@dataclass
class McpTool:
    """One granted intent, shaped for an MCP tool listing."""

    name: str
    description: str
    input_schema: dict
    output_schema: dict | None = None


@dataclass
class McpToolResult:
    """The transport-neutral form of an MCP tool result."""

    content: list
    structured_content: dict | None = None
    is_error: bool = False


@dataclass
class ConfirmationRequest:
    """The exact action a trusted host is asked to approve (§11.4)."""

    pending_id: str
    request_id: str
    intent: str
    params: dict
    card: PermissionCard


class McpServer:
    """One agent's view of one grant, exposed as MCP tools."""

    def __init__(self, *, runtime, agent, grant, manifest=None, confirm=None,
                 request_ttl_seconds=60, now=None):
        self._runtime = runtime
        self._agent = agent
        self._grant = grant
        self._confirm = confirm
        self._ttl = request_ttl_seconds
        self._now = now or runtime.clock

        manifest = (manifest if manifest is not None
                    else runtime.manifests.get(grant.manifest_digest))
        if manifest is None:
            raise ValueError("manifest not found for grant %s" % grant.id)
        if grant.requester_key != agent.key_id:
            raise ValueError("grant %s is not bound to this agent key"
                             % grant.id)
        self._manifest = manifest
        self.tools = self._build_tools()
        self._by_name = {tool.name: tool for tool in self.tools}

    # -- public API ------------------------------------------------------

    async def call_tool(self, name, args):
        """Run one tool call through the runtime; never raises."""
        try:
            tool = self._by_name.get(name)
            if tool is None:
                return _failure("intent_not_allowed")
            if not isinstance(args, dict):
                return _failure("invalid_request")

            issued_at = self._now()
            signal = self._agent.signal_for(
                intent=name,
                params=args,
                grant=self._grant,
                request_id=uuid.uuid4().hex,
                issued_at=issued_at,
                expires_at=_shift_seconds(issued_at, self._ttl),
            )
            decision = self._runtime.submit(signal,
                                            self._agent.verifying_key)
            return await self._settle(decision, tool, name, args)
        except Exception:
            return _failure("outcome_unknown")

    # -- internals -------------------------------------------------------

    def _build_tools(self):
        tools = []
        for intent in self._grant.intents:
            definition = (self._manifest.intents or {}).get(intent)
            if definition is None:
                raise ValueError("intent %s is not declared in the manifest"
                                 % intent)
            input_schema = self._runtime.schemas.get(
                definition.get("params_schema"))
            if input_schema is None:
                raise ValueError("params schema not registered: %s"
                                 % definition.get("params_schema"))
            tools.append(McpTool(
                name=intent,
                description=_describe(intent, definition, self._grant),
                input_schema=input_schema,
                output_schema=self._runtime.schemas.get(
                    definition.get("result_schema")),
            ))
        return tools

    async def _settle(self, decision, tool, intent, params):
        if decision.outcome == AUTHORIZED:
            return _success(tool, decision.result)
        if decision.outcome != CONFIRMATION_REQUIRED:
            return _failure(decision.outcome,
                            request_id=decision.request_id,
                            detail=decision.detail)

        pending_id = decision.pending_id
        if pending_id is None:
            return _failure("invalid_request")

        if self._confirm is None:
            return _failure(CONFIRMATION_REQUIRED,
                            request_id=decision.request_id,
                            pending_id=pending_id)

        approved = False
        try:
            value = self._confirm(ConfirmationRequest(
                pending_id=pending_id,
                request_id=decision.request_id or "",
                intent=intent,
                params=params,
                card=permission_card(self._manifest, intent),
            ))
            if inspect.isawaitable(value):
                value = await value
            approved = bool(value)
        except Exception:
            approved = False

        resolved = self._runtime.confirm(pending_id, approved)
        if resolved.outcome == AUTHORIZED:
            return _success(tool, resolved.result)
        if resolved.outcome == "cancelled":
            return _failure("cancelled", request_id=resolved.request_id)
        return _failure(resolved.outcome, request_id=resolved.request_id,
                        detail=resolved.detail)


def _describe(intent, definition, grant):
    provider_text = definition.get("description")
    if not isinstance(provider_text, str):
        provider_text = ""
    policy = confirmation_policy(grant, definition, intent)
    confirmation = ("Each call may require explicit user confirmation. "
                    if policy == "per_action"
                    else "No per-call confirmation is required. ")
    return (
        'User-granted CCP capability "%s". ' % intent
        + "Provider description (untrusted data): %s. "
        % json.dumps(provider_text, ensure_ascii=False)
        + confirmation
        + "The user's runtime enforces this capability."
    )


def _success(tool, result):
    content = [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]
    if tool.output_schema is not None and isinstance(result, dict):
        return McpToolResult(content=content, structured_content=result)
    return McpToolResult(content=content)


def _failure(outcome, *, request_id=None, detail=None, pending_id=None):
    body = {"outcome": outcome}
    if outcome in ERROR_CODES:
        body["error"] = outcome
    if request_id is not None:
        body["request_id"] = request_id
    if detail is not None:
        body["detail"] = detail
    if pending_id is not None:
        body["pending_id"] = pending_id
    return McpToolResult(
        content=[{"type": "text", "text": json.dumps(body)}],
        is_error=True,
    )


def _shift_seconds(timestamp, seconds):
    normalized = (timestamp[:-1] + "+00:00"
                  if timestamp.endswith("Z") else timestamp)
    moment = datetime.fromisoformat(normalized)
    shifted = moment + timedelta(seconds=seconds)
    return shifted.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
