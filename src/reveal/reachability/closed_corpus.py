"""Closed-corpus vulnerability evidence retrieval."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from reveal.exceptions import EvidenceRetrievalError
from reveal.models import Vulnerability, VulnerabilityEvidence


@dataclass(frozen=True, slots=True)
class _CorpusEntry:
    """Normalized internal representation of one corpus entry."""

    source: str
    content: str
    id: str | None = None
    aliases: tuple[str, ...] = ()
    package: str | None = None
    title: str | None = None
    reference: str | None = None


class ClosedCorpusEvidenceRetriever:
    """Retrieve vulnerability evidence from a local JSON corpus."""

    def __init__(self, corpus_path: Path) -> None:
        self.corpus_path = corpus_path
        self._entries: tuple[_CorpusEntry, ...] | None = None

    def retrieve(
        self,
        vulnerability: Vulnerability,
        *,
        limit: int = 5,
    ) -> tuple[VulnerabilityEvidence, ...]:
        """Return the most relevant evidence for a vulnerability."""

        if limit < 1:
            raise ValueError("limit must be at least one")

        ranked: list[tuple[float, _CorpusEntry]] = []

        for entry in self._load_entries():
            score = _score_entry(
                vulnerability=vulnerability,
                entry=entry,
            )

            if score > 0.0:
                ranked.append((score, entry))

        ranked.sort(
            key=lambda item: (
                -item[0],
                item[1].source,
                item[1].title or "",
            )
        )

        evidence: list[VulnerabilityEvidence] = []
        seen: set[tuple[str, str | None, str]] = set()

        for score, entry in ranked:
            key = (
                entry.source,
                entry.reference,
                entry.content,
            )

            if key in seen:
                continue

            seen.add(key)
            evidence.append(
                VulnerabilityEvidence(
                    source=entry.source,
                    title=entry.title,
                    content=entry.content,
                    reference=entry.reference or entry.id,
                    score=round(score, 4),
                )
            )

            if len(evidence) >= limit:
                break

        return tuple(evidence)

    def _load_entries(self) -> tuple[_CorpusEntry, ...]:
        if self._entries is not None:
            return self._entries

        if not self.corpus_path.is_file():
            raise EvidenceRetrievalError(
                f"Vulnerability corpus does not exist: {self.corpus_path}"
            )

        try:
            value: object = json.loads(
                self.corpus_path.read_text(encoding="utf-8")
            )
        except OSError as error:
            raise EvidenceRetrievalError(
                f"Failed to read vulnerability corpus: {self.corpus_path}"
            ) from error
        except json.JSONDecodeError as error:
            raise EvidenceRetrievalError(
                f"Vulnerability corpus contains invalid JSON: {self.corpus_path}"
            ) from error

        if not isinstance(value, dict):
            raise EvidenceRetrievalError(
                "Vulnerability corpus root must be a JSON object."
            )

        document = cast(dict[str, object], value)
        raw_entries = document.get("entries")

        if not isinstance(raw_entries, list):
            raise EvidenceRetrievalError(
                "Vulnerability corpus must contain an entries array."
            )

        entries = tuple(
            _parse_entry(raw_entry, index)
            for index, raw_entry in enumerate(
                cast(list[object], raw_entries),
                start=1,
            )
        )

        self._entries = entries
        return entries


def _parse_entry(value: object, index: int) -> _CorpusEntry:
    if not isinstance(value, dict):
        raise EvidenceRetrievalError(
            f"Corpus entry {index} must be a JSON object."
        )

    entry = cast(dict[str, object], value)

    source = _required_string(
        entry.get("source"),
        field="source",
        index=index,
    )
    content = _required_string(
        entry.get("content"),
        field="content",
        index=index,
    )
    entry_id = _optional_string(
        entry.get("id"),
        field="id",
        index=index,
    )
    aliases = _string_tuple(
        entry.get("aliases"),
        field="aliases",
        index=index,
    )
    package = _optional_string(
        entry.get("package"),
        field="package",
        index=index,
    )

    if entry_id is None and not aliases and package is None:
        raise EvidenceRetrievalError(
            f"Corpus entry {index} must define id, aliases, or package."
        )

    return _CorpusEntry(
        source=source,
        content=content,
        id=entry_id,
        aliases=aliases,
        package=package,
        title=_optional_string(
            entry.get("title"),
            field="title",
            index=index,
        ),
        reference=_optional_string(
            entry.get("reference"),
            field="reference",
            index=index,
        ),
    )


def _score_entry(
    vulnerability: Vulnerability,
    entry: _CorpusEntry,
) -> float:
    vulnerability_id = _normalize_identifier(vulnerability.id)
    query_ids = {
        vulnerability_id,
        *(
            _normalize_identifier(alias)
            for alias in vulnerability.aliases
        ),
    }

    entry_ids = {
        *(
            {_normalize_identifier(entry.id)}
            if entry.id is not None
            else set()
        ),
        *(
            _normalize_identifier(alias)
            for alias in entry.aliases
        ),
    }

    if entry.id is not None:
        if vulnerability_id == _normalize_identifier(entry.id):
            return 1.0

    if query_ids.intersection(entry_ids):
        return 0.95

    package_matches = (
        entry.package is not None
        and entry.package.casefold()
        == vulnerability.component.name.casefold()
    )

    description_score = _description_overlap(
        vulnerability.description,
        " ".join(
            value
            for value in (
                entry.title,
                entry.content,
            )
            if value is not None
        ),
    )

    if not package_matches and description_score < 0.2:
        return 0.0

    score = description_score * 0.5

    if package_matches:
        score += 0.4

    return min(score, 0.9)


def _description_overlap(query: str, candidate: str) -> float:
    query_tokens = _tokenize(query)

    if not query_tokens:
        return 0.0

    candidate_tokens = _tokenize(candidate)

    if not candidate_tokens:
        return 0.0

    return len(query_tokens.intersection(candidate_tokens)) / len(
        query_tokens
    )


def _tokenize(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9]+", value.casefold())
        if len(token) > 1
    }


def _normalize_identifier(value: str) -> str:
    return value.strip().casefold()


def _required_string(
    value: object,
    *,
    field: str,
    index: int,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceRetrievalError(
            f"Corpus entry {index} field {field} must be a non-empty string."
        )

    return value.strip()


def _optional_string(
    value: object,
    *,
    field: str,
    index: int,
) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise EvidenceRetrievalError(
            f"Corpus entry {index} field {field} must be a string."
        )

    normalized = value.strip()

    return normalized or None


def _string_tuple(
    value: object,
    *,
    field: str,
    index: int,
) -> tuple[str, ...]:
    if value is None:
        return ()

    if not isinstance(value, list):
        raise EvidenceRetrievalError(
            f"Corpus entry {index} field {field} must be an array."
        )

    result: list[str] = []

    for item in cast(list[object], value):
        if not isinstance(item, str) or not item.strip():
            raise EvidenceRetrievalError(
                f"Corpus entry {index} field {field} "
                "must contain non-empty strings."
            )

        normalized = item.strip()

        if normalized not in result:
            result.append(normalized)

    return tuple(result)