"""Default policy for converting REVEAL evidence into VEX statements."""

from __future__ import annotations

from collections.abc import Sequence

from reveal.exceptions import VexDecisionError
from reveal.models import (
    ApiMappingResult,
    ApiMappingStatus,
    PocResult,
    ReachabilityStatus,
    ReproductionStatus,
    TaintResult,
    VexStatement,
    VexStatus,
    Vulnerability,
)

_VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = (
    "vulnerable_code_not_in_execute_path"
)
_VULNERABLE_CODE_CANNOT_BE_CONTROLLED = (
    "vulnerable_code_cannot_be_controlled_by_adversary"
)


class DefaultVexDecisionPolicy:
    """Apply conservative VEX decisions to REVEAL analysis evidence."""

    def decide(
        self,
        vulnerability: Vulnerability,
        mapping: ApiMappingResult,
        taint_results: Sequence[TaintResult],
        poc_results: Sequence[PocResult],
    ) -> VexStatement:
        """Return a conservative VEX statement for one vulnerability."""

        normalized_taint = tuple(taint_results)
        normalized_pocs = tuple(poc_results)

        _validate_evidence(
            vulnerability=vulnerability,
            mapping=mapping,
            taint_results=normalized_taint,
            poc_results=normalized_pocs,
        )

        products = (_product_identifier(vulnerability),)

        if mapping.status is ApiMappingStatus.UNUSED:
            return VexStatement(
                vulnerability_id=vulnerability.id,
                products=products,
                status=VexStatus.NOT_AFFECTED,
                justification=_VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                impact_statement=(
                    "The vulnerable dependency is present, but no application "
                    "usage of the package was observed."
                ),
            )

        if mapping.status is not ApiMappingStatus.MAPPED:
            return VexStatement(
                vulnerability_id=vulnerability.id,
                products=products,
                status=VexStatus.UNDER_INVESTIGATION,
                impact_statement=_mapping_uncertainty(mapping),
            )

        reproduced = next(
            (
                result
                for result in normalized_pocs
                if result.status is ReproductionStatus.REPRODUCED
            ),
            None,
        )

        if reproduced is not None:
            return VexStatement(
                vulnerability_id=vulnerability.id,
                products=products,
                status=VexStatus.AFFECTED,
                impact_statement=(
                    reproduced.evidence
                    or "A proof of concept reproduced the vulnerable behavior."
                ),
                action_statement=_remediation_action(vulnerability),
            )

        target_apis = _unique_strings(mapping.target_apis)

        if not target_apis:
            return VexStatement(
                vulnerability_id=vulnerability.id,
                products=products,
                status=VexStatus.UNDER_INVESTIGATION,
                impact_statement=(
                    "The API mapping was marked as successful but did not "
                    "identify any target APIs."
                ),
            )

        if _all_targets_unreachable(
            target_apis=target_apis,
            taint_results=normalized_taint,
        ):
            return VexStatement(
                vulnerability_id=vulnerability.id,
                products=products,
                status=VexStatus.NOT_AFFECTED,
                justification=_VULNERABLE_CODE_CANNOT_BE_CONTROLLED,
                impact_statement=(
                    "Reachability analysis found no attacker-controlled "
                    "input flow to any mapped vulnerable API."
                ),
            )

        return VexStatement(
            vulnerability_id=vulnerability.id,
            products=products,
            status=VexStatus.UNDER_INVESTIGATION,
            impact_statement=_investigation_reason(
                taint_results=normalized_taint,
                poc_results=normalized_pocs,
            ),
        )


def _validate_evidence(
    *,
    vulnerability: Vulnerability,
    mapping: ApiMappingResult,
    taint_results: tuple[TaintResult, ...],
    poc_results: tuple[PocResult, ...],
) -> None:
    if mapping.vulnerability_id != vulnerability.id:
        raise VexDecisionError(
            "API mapping vulnerability does not match the requested "
            "vulnerability."
        )

    for taint_result in taint_results:
        if taint_result.vulnerability_id != vulnerability.id:
            raise VexDecisionError(
                "Taint result vulnerability does not match the requested "
                "vulnerability."
            )

    for poc_result in poc_results:
        if poc_result.vulnerability_id != vulnerability.id:
            raise VexDecisionError(
                "PoC result vulnerability does not match the requested "
                "vulnerability."
            )

    if mapping.status is not ApiMappingStatus.MAPPED:
        if taint_results or poc_results:
            raise VexDecisionError(
                "Downstream reachability or reproduction evidence requires "
                "a mapped vulnerable API."
            )

        return

    mapped_apis = set(mapping.target_apis)

    for taint_result in taint_results:
        if taint_result.target_api not in mapped_apis:
            raise VexDecisionError(
                "Taint result references an API that was not selected by "
                f"the API mapping stage: {taint_result.target_api}"
            )

    for poc_result in poc_results:
        if poc_result.target_api not in mapped_apis:
            raise VexDecisionError(
                "PoC result references an API that was not selected by "
                f"the API mapping stage: {poc_result.target_api}"
            )


def _all_targets_unreachable(
    *,
    target_apis: tuple[str, ...],
    taint_results: tuple[TaintResult, ...],
) -> bool:
    results_by_api: dict[str, list[TaintResult]] = {}

    for result in taint_results:
        results_by_api.setdefault(
            result.target_api,
            [],
        ).append(result)

    for target_api in target_apis:
        results = results_by_api.get(target_api)

        if not results:
            return False

        if any(
            result.status is not ReachabilityStatus.UNREACHABLE
            for result in results
        ):
            return False

    return True


def _mapping_uncertainty(mapping: ApiMappingResult) -> str:
    if mapping.rationale.strip():
        return mapping.rationale

    if mapping.status is ApiMappingStatus.ERROR:
        return "Vulnerable API mapping failed."

    return (
        "The available vulnerability evidence was insufficient to identify "
        "a vulnerable API used by the application."
    )


def _investigation_reason(
    *,
    taint_results: tuple[TaintResult, ...],
    poc_results: tuple[PocResult, ...],
) -> str:
    if any(
        result.status is ReproductionStatus.NOT_REPRODUCED
        for result in poc_results
    ):
        return (
            "Generated PoC candidates did not reproduce the vulnerability. "
            "This does not establish that the product is not affected."
        )

    if any(
        result.status
        in {
            ReproductionStatus.INCONCLUSIVE,
            ReproductionStatus.ERROR,
        }
        for result in poc_results
    ):
        return (
            "PoC execution was incomplete or inconclusive, so exploitability "
            "has not been determined."
        )

    if any(
        result.status is ReachabilityStatus.REACHABLE
        for result in taint_results
    ):
        return (
            "Attacker-controlled input can reach a mapped vulnerable API, "
            "but successful vulnerability reproduction has not been confirmed."
        )

    if any(
        result.status
        in {
            ReachabilityStatus.UNKNOWN,
            ReachabilityStatus.ERROR,
        }
        for result in taint_results
    ):
        return (
            "Reachability analysis did not produce a definitive result for "
            "every mapped vulnerable API."
        )

    if not taint_results:
        return (
            "A vulnerable API was mapped, but taint reachability analysis has "
            "not been completed."
        )

    if any(
        result.status is ReproductionStatus.SKIPPED
        for result in poc_results
    ):
        return "PoC reproduction was skipped and exploitability remains unknown."

    return (
        "The available evidence is insufficient to determine whether the "
        "vulnerability is exploitable in this product."
    )


def _remediation_action(vulnerability: Vulnerability) -> str:
    if vulnerability.fixed_versions:
        versions = ", ".join(vulnerability.fixed_versions)

        return (
            f"Update {vulnerability.component.name} to one of the reported "
            f"fixed versions: {versions}."
        )

    return (
        f"Update or otherwise mitigate {vulnerability.component.name} "
        "according to the upstream advisory."
    )


def _product_identifier(vulnerability: Vulnerability) -> str:
    component = vulnerability.component

    if component.purl is not None and component.purl.strip():
        return component.purl

    return (
        f"{component.ecosystem}:{component.name}@{component.version}"
    )


def _unique_strings(values: Sequence[str]) -> tuple[str, ...]:
    unique: list[str] = []

    for value in values:
        if value not in unique:
            unique.append(value)

    return tuple(unique)