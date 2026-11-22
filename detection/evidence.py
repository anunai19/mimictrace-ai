import json
import math
from dataclasses import dataclass
from typing import Any, Dict, List, Literal


EvidenceStatus = Literal["observed", "unavailable", "error", "not_run"]
_ALLOWED_STATUSES = frozenset({"observed", "unavailable", "error", "not_run"})


def _validate_json_value(value: Any, path: str, active_containers: set) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite number.")
        return
    if isinstance(value, list):
        identity = id(value)
        if identity in active_containers:
            raise ValueError(f"{path} contains a circular reference.")
        active_containers.add(identity)
        try:
            for index, item in enumerate(value):
                _validate_json_value(item, f"{path}[{index}]", active_containers)
        finally:
            active_containers.remove(identity)
        return
    if isinstance(value, dict):
        identity = id(value)
        if identity in active_containers:
            raise ValueError(f"{path} contains a circular reference.")
        active_containers.add(identity)
        try:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ValueError(f"{path} contains a non-string object key.")
                _validate_json_value(item, f"{path}.{key}", active_containers)
        finally:
            active_containers.remove(identity)
        return
    raise ValueError(f"{path} contains a value that is not JSON-safe.")


@dataclass(frozen=True)
class EvidenceRecord:
    source: str
    observation: Dict[str, Any]
    status: EvidenceStatus
    uncertainty: List[str]

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("Evidence source must be a non-empty string.")
        if not isinstance(self.status, str) or self.status not in _ALLOWED_STATUSES:
            raise ValueError("Evidence status is not supported.")
        if not isinstance(self.observation, dict):
            raise ValueError("Evidence observation must be an object.")
        _validate_json_value(self.observation, "observation", set())
        if not isinstance(self.uncertainty, list) or any(
            not isinstance(reason, str) or not reason.strip()
            for reason in self.uncertainty
        ):
            raise ValueError(
                "Evidence uncertainty must be a list of non-empty reason strings."
            )

    def to_dict(self) -> Dict[str, Any]:
        self._validate()
        serialized = json.dumps(
            {
                "source": self.source,
                "observation": self.observation,
                "status": self.status,
                "uncertainty": self.uncertainty,
            },
            allow_nan=False,
            ensure_ascii=False,
        )
        return json.loads(serialized)

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
        )
