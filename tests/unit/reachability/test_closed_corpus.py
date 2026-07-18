"""Tests for the closed-corpus vulnerability evidence retriever."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reveal.exceptions import EvidenceRetrievalError
from reveal.models import Component, Vulnerability
from reveal.reachability.closed_corpus import (
    ClosedCorpusEvidenceRetriever,
)


def create_vulnerability() -> Vulnerability:
    component = Component(
        name="minimist",
        version="0.0.8",
        ecosystem="npm",
        purl="pkg:npm/minimist@0.0.8",
    )

    return Vulnerability(
        id="GHSA-xvch-5gv4-984h",
        component=component,
        aliases=("CVE-2021-44906",),
        description="Prototype pollution through parsed property paths.",
    )


def write_corpus(
    path: Path,
    entries: list[dict[str, object]],
) -> None:
    path.write_text(
        json.dumps({"entries": entries}),
        encoding="utf-8",
    )


def test_retrieve_prioritizes_exact_vulnerability_id(
    tmp_path: Path,
) -> None:
    corpus_path = tmp_path / "corpus.json"
    write_corpus(
        corpus_path,
        [
            {
                "package": "minimist",
                "source": "package-documentation",
                "title": "minimist parser",
                "content": "The package parses command line arguments.",
            },
            {
                "id": "GHSA-xvch-5gv4-984h",
                "aliases": ["CVE-2021-44906"],
                "package": "minimist",
                "source": "github-advisory",
                "title": "Prototype pollution in minimist",
                "content": (
                    "Affected versions allow prototype pollution "
                    "through parsed property paths."
                ),
                "reference": "GHSA-xvch-5gv4-984h",
            },
        ],
    )

    retriever = ClosedCorpusEvidenceRetriever(corpus_path)

    result = retriever.retrieve(create_vulnerability())

    assert len(result) == 2
    assert result[0].source == "github-advisory"
    assert result[0].reference == "GHSA-xvch-5gv4-984h"
    assert result[0].score == 1.0


def test_retrieve_matches_vulnerability_alias(
    tmp_path: Path,
) -> None:
    corpus_path = tmp_path / "corpus.json"
    write_corpus(
        corpus_path,
        [
            {
                "id": "CVE-2021-44906",
                "source": "nvd",
                "content": "Prototype pollution in minimist.",
            }
        ],
    )

    retriever = ClosedCorpusEvidenceRetriever(corpus_path)

    result = retriever.retrieve(create_vulnerability())

    assert len(result) == 1
    assert result[0].source == "nvd"
    assert result[0].score == 0.95


def test_retrieve_uses_package_and_description_similarity(
    tmp_path: Path,
) -> None:
    corpus_path = tmp_path / "corpus.json"
    write_corpus(
        corpus_path,
        [
            {
                "package": "minimist",
                "source": "package-advisory",
                "title": "Prototype pollution",
                "content": (
                    "Parsed property paths can modify an object prototype."
                ),
            },
            {
                "package": "unrelated-package",
                "source": "unrelated",
                "content": "A denial of service caused by regular expressions.",
            },
        ],
    )

    retriever = ClosedCorpusEvidenceRetriever(corpus_path)

    result = retriever.retrieve(create_vulnerability())

    assert len(result) == 1
    assert result[0].source == "package-advisory"
    assert result[0].score is not None
    assert 0.4 <= result[0].score <= 0.9


def test_retrieve_respects_limit(tmp_path: Path) -> None:
    corpus_path = tmp_path / "corpus.json"
    write_corpus(
        corpus_path,
        [
            {
                "id": "GHSA-xvch-5gv4-984h",
                "source": "source-one",
                "content": "First evidence.",
            },
            {
                "aliases": ["CVE-2021-44906"],
                "source": "source-two",
                "content": "Second evidence.",
            },
        ],
    )

    retriever = ClosedCorpusEvidenceRetriever(corpus_path)

    result = retriever.retrieve(
        create_vulnerability(),
        limit=1,
    )

    assert len(result) == 1
    assert result[0].source == "source-one"


def test_retrieve_rejects_missing_corpus(
    tmp_path: Path,
) -> None:
    retriever = ClosedCorpusEvidenceRetriever(
        tmp_path / "missing.json"
    )

    with pytest.raises(
        EvidenceRetrievalError,
        match="does not exist",
    ):
        retriever.retrieve(create_vulnerability())


def test_retrieve_rejects_invalid_json(
    tmp_path: Path,
) -> None:
    corpus_path = tmp_path / "corpus.json"
    corpus_path.write_text(
        "not valid JSON",
        encoding="utf-8",
    )

    retriever = ClosedCorpusEvidenceRetriever(corpus_path)

    with pytest.raises(
        EvidenceRetrievalError,
        match="invalid JSON",
    ):
        retriever.retrieve(create_vulnerability())


def test_retrieve_rejects_invalid_entry(
    tmp_path: Path,
) -> None:
    corpus_path = tmp_path / "corpus.json"
    write_corpus(
        corpus_path,
        [
            {
                "source": "github-advisory",
                "content": "Evidence without a lookup key.",
            }
        ],
    )

    retriever = ClosedCorpusEvidenceRetriever(corpus_path)

    with pytest.raises(
        EvidenceRetrievalError,
        match="must define id, aliases, or package",
    ):
        retriever.retrieve(create_vulnerability())


def test_retrieve_rejects_non_positive_limit(
    tmp_path: Path,
) -> None:
    corpus_path = tmp_path / "corpus.json"
    write_corpus(corpus_path, [])

    retriever = ClosedCorpusEvidenceRetriever(corpus_path)

    with pytest.raises(
        ValueError,
        match="at least one",
    ):
        retriever.retrieve(
            create_vulnerability(),
            limit=0,
        )