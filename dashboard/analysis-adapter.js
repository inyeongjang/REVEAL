const SEVERITIES = new Set([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
]);

export function toDashboardResult(analysis, metadata = {}) {
  const components = analysis?.scan?.sbom?.components ?? [];
  const analyses = analysis?.analyses ?? [];
  const source = metadata.source ?? "";

  const repositoryName = getRepositoryName(source);
  const rootComponent = findRootComponent(
    components,
    repositoryName,
  );

  return {
    packageName:
      rootComponent?.name ||
      repositoryName ||
      "unknown-package",

    packageVersion:
      rootComponent?.version ||
      "unknown",

    analyzedAt:
      analysis?.generated_at ||
      new Date().toISOString(),

    commitSha:
      metadata.commitSha ||
      "",

    stats: buildStats(analysis, analyses),

    sbomComponents: components
      .filter((component) => component?.purl)
      .map((component) => ({
        name: component.name ?? "unknown",
        version: component.version ?? "",
        purl: component.purl,
        licenses: normalizeLicenses(component.licenses),
      })),

    vexEntries: analyses.map((item) =>
      toVexEntry(item),
    ),

    pipelineLog: Array.isArray(metadata.pipelineLog)
      ? metadata.pipelineLog
      : [],
  };
}

function toVexEntry(item) {
  const vulnerability = item?.vulnerability ?? {};
  const component = vulnerability?.component ?? {};
  const mapping = item?.mapping ?? {};
  const vex = item?.vex_statement ?? {};

  const pocResults = Array.isArray(item?.poc_results)
    ? item.poc_results
    : [];

  const taintResults = Array.isArray(
    item?.taint_results,
  )
    ? item.taint_results
    : [];

  const successfulPoc = pocResults.find(
    isSuccessfulPoc,
  );

  const fixedVersions = Array.isArray(
    vulnerability.fixed_versions,
  )
    ? vulnerability.fixed_versions
    : [];

  return {
    id:
      vulnerability.id ||
      vex.vulnerability_id ||
      "UNKNOWN",

    cve:
      findCve(vulnerability.aliases) ||
      vulnerability.id ||
      "UNKNOWN",

    cwe: normalizeCwes(
      vulnerability.cwe ?? vulnerability.cwes,
    ),

    severity: normalizeSeverity(
      vulnerability.severity,
    ),

    cvss: normalizeCvss(
      vulnerability.cvss ??
        vulnerability.cvss_score ??
        vulnerability.cvssScore,
    ),

    description:
      vulnerability.description ||
      "No vulnerability description is available.",

    component:
      component.name ||
      getProductName(vex.products) ||
      "unknown",

    version:
      component.version ||
      getProductVersion(vex.products) ||
      "",

    vexStatus: toDashboardStatus(vex.status),

    justification:
      vex.impact_statement ||
      vex.justification ||
      mapping.rationale ||
      "No justification was provided.",

    pocAvailable: Boolean(successfulPoc),

    pocVector: extractPocCode(successfulPoc),

    codeqlQuery: extractCodeqlSummary(
      taintResults,
      mapping,
    ),

    affectedLines:
      extractAffectedLines(taintResults),

    recommendation:
      vex.action_statement ||
      buildUpgradeRecommendation(
        component.name,
        fixedVersions,
      ),
  };
}

function buildStats(analysis, analyses) {
  const counts =
    analysis?.summary?.vex_status_counts ?? {};

  const total =
    analysis?.summary?.vulnerability_count ??
    analyses.length;

  const exploitable = numberValue(counts.affected);
  const notAffected = numberValue(
    counts.not_affected,
  );
  const fixed = numberValue(counts.fixed);
  const underInvestigation = numberValue(
    counts.under_investigation,
  );

  return {
    total,
    exploitable,
    affected: exploitable,
    not_exploitable: fixed,
    not_affected: notAffected,
    fixed,
    under_investigation: underInvestigation,
  };
}

function toDashboardStatus(status) {
  switch (String(status ?? "").toLowerCase()) {
    case "affected":
    case "exploitable":
      return "EXPLOITABLE";

    case "not_affected":
      return "NOT_AFFECTED";

    case "fixed":
    case "not_exploitable":
      return "NOT_EXPLOITABLE";

    default:
      return "UNDER_INVESTIGATION";
  }
}

function normalizeSeverity(value) {
  const severity = String(
    value ?? "LOW",
  ).toUpperCase();

  return SEVERITIES.has(severity)
    ? severity
    : "LOW";
}

function normalizeCvss(value) {
  const score = Number(value);

  return Number.isFinite(score)
    ? score
    : 0;
}

function normalizeLicenses(value) {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .map((license) => {
      if (typeof license === "string") {
        return license;
      }

      return license?.name ?? license?.id ?? "";
    })
    .filter(Boolean);
}

function normalizeCwes(value) {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .map((cwe) => String(cwe))
    .filter(Boolean);
}

function findCve(aliases) {
  if (!Array.isArray(aliases)) {
    return "";
  }

  return (
    aliases.find((alias) =>
      /^CVE-\d{4}-\d+$/i.test(alias),
    ) ?? ""
  );
}

function findRootComponent(
  components,
  repositoryName,
) {
  if (!repositoryName) {
    return components.find(
      (component) =>
        component?.ecosystem === "npm" &&
        component?.version,
    );
  }

  return (
    components.find(
      (component) =>
        component?.name?.toLowerCase() ===
        repositoryName.toLowerCase(),
    ) ||
    components.find(
      (component) =>
        component?.ecosystem === "npm" &&
        component?.version,
    )
  );
}

function getRepositoryName(source) {
  if (typeof source !== "string") {
    return "";
  }

  const match = source
    .trim()
    .match(
      /^https:\/\/github\.com\/[^/]+\/([^/#?]+?)(?:\.git)?\/?$/,
    );

  return match?.[1] ?? "";
}

function getProductName(products) {
  const purl = Array.isArray(products)
    ? products[0]
    : "";

  const match = String(purl).match(
    /^pkg:[^/]+\/(.+?)@([^@]+)$/,
  );

  return match?.[1] ?? "";
}

function getProductVersion(products) {
  const purl = Array.isArray(products)
    ? products[0]
    : "";

  const match = String(purl).match(
    /^pkg:[^/]+\/(.+?)@([^@]+)$/,
  );

  return match?.[2] ?? "";
}

function isSuccessfulPoc(result) {
  const status = String(
    result?.status ??
      result?.reproduction_status ??
      result?.reproductionStatus ??
      "",
  ).toLowerCase();

  return [
    "success",
    "succeeded",
    "reproduced",
    "exploitable",
    "confirmed",
  ].includes(status);
}

function extractPocCode(result) {
  if (!result) {
    return "";
  }

  return (
    result?.candidate?.code ||
    result?.candidate?.script ||
    result?.code ||
    result?.script ||
    result?.poc ||
    ""
  );
}

function extractCodeqlSummary(
  taintResults,
  mapping,
) {
  for (const result of taintResults) {
    const value =
      result?.query_id ||
      result?.query_name ||
      result?.query ||
      result?.rule_id;

    if (value) {
      return String(value);
    }
  }

  const targetApis = Array.isArray(
    mapping?.target_apis,
  )
    ? mapping.target_apis
    : [];

  return targetApis.length > 0
    ? targetApis.join(", ")
    : "N/A";
}

function extractAffectedLines(taintResults) {
  const locations = new Set();

  for (const result of taintResults) {
    addLocation(locations, result);
    addLocation(locations, result?.source);
    addLocation(locations, result?.sink);

    for (const step of result?.path ?? []) {
      addLocation(locations, step);
    }

    for (const pathItem of result?.paths ?? []) {
      addLocation(locations, pathItem);

      for (
        const step of
        pathItem?.steps ??
        pathItem?.path ??
        []
      ) {
        addLocation(locations, step);
      }
    }
  }

  return [...locations];
}

function addLocation(target, value) {
  if (!value || typeof value !== "object") {
    return;
  }

  const file =
    value.file ||
    value.path ||
    value.filename ||
    value.location?.file ||
    value.location?.path;

  const line =
    value.line ||
    value.start_line ||
    value.startLine ||
    value.location?.line ||
    value.location?.start_line ||
    value.location?.startLine;

  if (file && line) {
    target.add(`${file}:${line}`);
  }
}

function buildUpgradeRecommendation(
  componentName,
  fixedVersions,
) {
  if (fixedVersions.length === 0) {
    return (
      "Review the finding and apply the " +
      "appropriate remediation."
    );
  }

  const name =
    componentName ||
    "the affected component";

  return `Upgrade ${name} to ${fixedVersions[0]} or later.`;
}

function numberValue(value) {
  const number = Number(value);

  return Number.isFinite(number)
    ? number
    : 0;
}