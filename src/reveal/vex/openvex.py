"""OpenVEX JSON document generation."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from reveal.exceptions import VexWriteError
from reveal.models import VexStatement, VexStatus

_OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

_ALLOWED_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}

_IRI_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


class OpenVexWriter:
    """Serialize REVEAL VEX statements as an OpenVEX 0.2.0 document."""

    def __init__(
        self,
        *,
        author: str,
        document_id: str,
        role: str | None = "Document Creator",
        version: int = 1,
        tooling: str | None = "REVEAL",
    ) -> None:
        if not author.strip():
            raise ValueError("author must not be empty")

        if not _is_iri(document_id):
            raise ValueError("document_id must be a valid absolute IRI")

        if version < 1:
            raise ValueError("version must be at least one")

        self.author = author.strip()
        self.document_id = document_id.strip()
        self.role = _optional_text(role)
        self.version = version
        self.tooling = _optional_text(tooling)

    def write(
        self,
        statements: Sequence[VexStatement],
        output_path: Path,
        *,
        timestamp: datetime | None = None,
    ) -> Path:
        """Write a complete OpenVEX document."""

        normalized_statements = tuple(statements)

        if not normalized_statements:
            raise VexWriteError(
                "An OpenVEX document must contain at least one statement."
            )

        issued_at = timestamp or datetime.now(timezone.utc)
        formatted_timestamp = _format_timestamp(issued_at)

        statement_documents = _deduplicate_statements(
            [
                _serialize_statement(statement)
                for statement in normalized_statements
            ]
        )

        document: dict[str, object] = {
            "@context": _OPENVEX_CONTEXT,
            "@id": self.document_id,
            "author": self.author,
            "timestamp": formatted_timestamp,
            "version": self.version,
            "statements": statement_documents,
        }

        if self.role is not None:
            document["role"] = self.role

        if self.tooling is not None:
            document["tooling"] = self.tooling

        serialized = json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
        ) + "\n"

        try:
            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            output_path.write_text(
                serialized,
                encoding="utf-8",
            )
        except OSError as error:
            raise VexWriteError(
                f"Failed to write OpenVEX document: {output_path}"
            ) from error

        return output_path


def _serialize_statement(
    statement: VexStatement,
) -> dict[str, object]:
    vulnerability_id = statement.vulnerability_id.strip()
    products = _unique_nonempty_strings(statement.products)
    justification = _optional_text(statement.justification)
    impact_statement = _optional_text(statement.impact_statement)
    action_statement = _optional_text(statement.action_statement)

    if not vulnerability_id:
        raise VexWriteError(
            "VEX statement vulnerability_id must not be empty."
        )

    if not products:
        raise VexWriteError(
            f"VEX statement {vulnerability_id} must contain a product."
        )

    for product in products:
        if not _is_iri(product):
            raise VexWriteError(
                f"VEX statement product must be an absolute IRI: {product}"
            )

    if (
        justification is not None
        and justification not in _ALLOWED_JUSTIFICATIONS
    ):
        raise VexWriteError(
            f"Invalid OpenVEX justification: {justification}"
        )

    if (
        statement.status is VexStatus.NOT_AFFECTED
        and justification is None
        and impact_statement is None
    ):
        raise VexWriteError(
            "A not_affected statement requires a justification "
            "or impact_statement."
        )

    if (
        statement.status is VexStatus.AFFECTED
        and action_statement is None
    ):
        raise VexWriteError(
            "An affected statement requires an action_statement."
        )

    document: dict[str, object] = {
        "vulnerability": {
            "name": vulnerability_id,
        },
        "products": [
            {
                "@id": product,
            }
            for product in products
        ],
        "status": statement.status.value,
    }

    if justification is not None:
        document["justification"] = justification

    if impact_statement is not None:
        document["impact_statement"] = impact_statement

    if action_statement is not None:
        document["action_statement"] = action_statement

    return document


def _deduplicate_statements(
    statements: list[dict[str, object]],
) -> list[dict[str, object]]:
    unique: list[dict[str, object]] = []
    seen: set[str] = set()

    for statement in statements:
        key = json.dumps(
            statement,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(statement)

    return unique


def _format_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise VexWriteError(
            "OpenVEX timestamps must include timezone information."
        )

    normalized = value.astimezone(timezone.utc)

    return normalized.isoformat(
        timespec="seconds",
    ).replace(
        "+00:00",
        "Z",
    )


def _is_iri(value: str) -> bool:
    normalized = value.strip()

    return (
        bool(normalized)
        and not any(character.isspace() for character in normalized)
        and _IRI_PATTERN.match(normalized) is not None
    )


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None

    normalized = value.strip()

    return normalized or None


def _unique_nonempty_strings(
    values: Sequence[str],
) -> tuple[str, ...]:
    unique: list[str] = []

    for value in values:
        normalized = value.strip()

        if normalized and normalized not in unique:
            unique.append(normalized)

    return tuple(unique)