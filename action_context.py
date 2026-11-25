"""ActionContext — parsed action facts for enforcement decisions.

Frozen decision contract: detection findings are raw text; authorization is a
separate trusted input. This container is introduced at G1 without changing
any existing rule behaviour.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple


class SourceProvenance:
    OPERATOR = "operator"
    TOOL = "tool"
    WEB = "web"
    DOCUMENT = "document"
    UNKNOWN = "unknown"


class ActionAuthorization:
    EXPLICIT_GRANT = "explicit_grant"
    SCOPED_GRANT = "scoped_grant"
    TOOL_PERMISSION = "tool_permission"
    UNVERIFIED = "unverified"


@dataclass(frozen=True)
class ActionContext:
    tool_name: str
    args: Dict[str, Any]
    cwd: Optional[str] = None
    targets: Tuple[str, ...] = ()
    command: str = ""
    content: str = ""
    source_provenance: str = SourceProvenance.UNKNOWN
    action_authorization: str = ActionAuthorization.UNVERIFIED
    literal_vars: Dict[str, str] = field(default_factory=dict)
    scan_complete: bool = True

    def target_paths(self) -> Tuple[str, ...]:
        return tuple(str(t) for t in self.targets)
