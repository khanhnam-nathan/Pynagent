/**
 * GitHub API helpers for PR comments, inline reviews, and Checks API.
 *
 * Copyright (c) 2026 PyNEAT Authors
 * Licensed under GNU AGPL v3.
 */

"use strict";

const fs = require("fs");

// ---------------------------------------------------------------------------
// PR Comment formatting
// ---------------------------------------------------------------------------

/**
 * Generate the PR body comment with scan summary and findings.
 * @param {object} scanResult - Structured scan result from pyneat-wrapper
 * @param {object} options
 * @returns {string} Markdown body for the PR comment
 */
function generatePRBody(scanResult, options = {}) {
  const {
    showSnippets = false,
    maxFindings = 20,
    showFixHints = true,
    includeFooter = true,
  } = options;

  const {
    findings = [],
    severity_summary = {},
    total = 0,
    duration_seconds = 0,
    files_scanned = 0,
  } = scanResult;

  if (total === 0) {
    return generateEmptyBody(duration_seconds, files_scanned);
  }

  const sections = [];

  // Header
  sections.push(generateHeader(severity_summary, total));

  // Severity breakdown
  sections.push(generateSeverityBreakdown(severity_summary));

  // Detailed findings
  sections.push(generateFindingsSection(findings.slice(0, maxFindings), {
    showSnippets,
    showFixHints,
  }));

  // Summary table
  sections.push(generateSummaryTable(scanResult));

  // Footer
  if (includeFooter) {
    sections.push(generateFooter());
  }

  return sections.filter(Boolean).join("\n\n---\n\n");
}

/**
 * Generate the "no issues found" PR comment body.
 */
function generateEmptyBody(duration, files) {
  return [
    "## 🛡️ PyNEAT Security Scan — No Issues Found",
    "",
    `<sub>Scanned ${files} file(s) in ${duration.toFixed(1)}s</sub>`,
    "",
    "All checks passed. No security vulnerabilities, code quality issues, or secrets detected.",
    "",
    generateFooter(),
  ].join("\n");
}

/**
 * Generate the header section with overall status emoji.
 */
function generateHeader(severitySummary, total) {
  const critical = severitySummary.critical || 0;
  const high = severitySummary.high || 0;
  const medium = severitySummary.medium || 0;

  let status;
  if (critical > 0) {
    status = "🚨 **Critical Security Issues Detected**";
  } else if (high > 0) {
    status = "⚠️ **High Severity Issues Detected**";
  } else if (medium > 0) {
    status = "🟡 **Medium Severity Issues Found**";
  } else {
    status = "✅ **Issues Found (Low/Info)**";
  }

  return [
    `## 🛡️ PyNEAT Security Scan — ${total} Finding${total !== 1 ? "s" : ""}`,
    "",
    status,
    "",
    `This pull request has been scanned by [PyNEAT](https://github.com/pyneat/pyneat) with AI analysis powered by ${process.env.AMD_MODEL || "Qwen/Llama on AMD Cloud"}.`,
    "",
  ].join("\n");
}

/**
 * Generate severity breakdown emoji row.
 */
function generateSeverityBreakdown(severitySummary) {
  const rows = [
    ["🔴 Critical", severitySummary.critical || 0],
    ["🟠 High", severitySummary.high || 0],
    ["🟡 Medium", severitySummary.medium || 0],
    ["🔵 Low", severitySummary.low || 0],
    ["⚪ Info", severitySummary.info || 0],
  ].filter(([, count]) => count > 0);

  if (rows.length === 0) return "";

  return [
    "### Severity Breakdown",
    "",
    rows.map(([emoji, label]) => {
      const count = typeof label === "number" ? label : 0;
      return `${emoji} **${label}**: ${count}`;
    }).join("  \n"),
    "",
  ].join("\n");
}

/**
 * Generate the detailed findings section.
 */
function generateFindingsSection(findings, options = {}) {
  const { showSnippets = false, showFixHints = true } = options;

  const lines = ["### 📋 Detailed Findings", ""];

  // Group by severity
  const severityOrder = ["critical", "high", "medium", "low", "info"];
  const grouped = {};

  for (const sev of severityOrder) {
    grouped[sev] = findings.filter((f) => f.severity === sev);
  }

  for (const sev of severityOrder) {
    const sevFindings = grouped[sev];
    if (sevFindings.length === 0) continue;

    const emoji = {
      critical: "🔴",
      high: "🟠",
      medium: "🟡",
      low: "🔵",
      info: "⚪",
    }[sev];

    lines.push(`#### ${emoji} ${sev.toUpperCase()} Severity (${sevFindings.length})`);
    lines.push("");

    for (const finding of sevFindings) {
      lines.push(generateFindingEntry(finding, { showSnippets, showFixHints }));
      lines.push("");
    }
  }

  return lines.join("\n");
}

/**
 * Generate a single finding entry.
 */
function generateFindingEntry(finding, options = {}) {
  const { showSnippets, showFixHints } = options;
  const {
    rule_id = "unknown",
    message = "",
    file = "?",
    line = 0,
    cwe_id,
    owasp_id,
    cvss_score,
    snippet,
    marker_id,
    confidence,
    auto_fix_available,
  } = finding;

  const lines = [];

  // Title row with file location
  const loc = line > 0 ? `${file}:${line}` : file;
  const markerTag = marker_id ? ` \`${marker_id}\`` : "";
  lines.push(`**\`${rule_id}\`**${markerTag} at \`${loc}\``);
  lines.push("");

  // Main message
  lines.push(message);

  // Tags row
  const tags = [];
  if (cwe_id) tags.push(`[${cwe_id}](https://cwe.mitre.org/data/definitions/${cwe_id.replace("CWE-", "")}.html)`);
  if (owasp_id) tags.push(`[OWASP A${owasp_id}](https://owasp.org/Top10/)`);
  if (cvss_score) tags.push(`CVSS ${typeof cvss_score === "number" ? cvss_score.toFixed(1) : cvss_score}`);

  if (tags.length > 0) {
    lines.push("");
    lines.push(`> ${tags.join(" · ")}`);
  }

  // Code snippet
  if (showSnippets && snippet) {
    lines.push("");
    lines.push("```");
    const snippetText = typeof snippet === "string" ? snippet : (snippet.text || "");
    lines.push(snippetText.slice(0, 300));
    if (snippetText.length > 300) lines.push("... (truncated)");
    lines.push("```");
  }

  // Auto-fix availability
  if (auto_fix_available) {
    lines.push("");
    lines.push("> 🛠️ **Auto-fix available.** Run `pyneat fix --marker " + (marker_id || "MARKER_ID") + "` to apply the fix.");
  }

  // Confidence note
  if (confidence && confidence < 1.0) {
    const conf = typeof confidence === "number" ? confidence : parseFloat(confidence);
    lines.push("");
    lines.push(`> ⚠️ AI confidence: ${(conf * 100).toFixed(0}%} — please verify manually.`);
  }

  return lines.join("\n");
}

/**
 * Generate summary table.
 */
function generateSummaryTable(scanResult) {
  const {
    total = 0,
    security_count = 0,
    duration_seconds = 0,
    files_scanned = 0,
    languages = [],
  } = scanResult;

  return [
    "### 📊 Scan Summary",
    "",
    "| Metric | Value |",
    "|--------|-------|",
    `| Total Findings | ${total} |`,
    `| Security Issues | ${security_count} |`,
    `| Files Scanned | ${files_scanned} |`,
    `| Scan Duration | ${(duration_seconds || 0).toFixed(1)}s |`,
    `| Languages | ${(languages || []).join(", ") || "—"} |`,
    "",
  ].join("\n");
}

/**
 * Generate the footer with links.
 */
function generateFooter() {
  return [
    "---",
    "",
    "<sub>",
    "🤖 Scanned by [PyNEAT](https://github.com/pyneat/pyneat) v3.0 · ",
    "AI analysis by AMD Cloud (Qwen/Llama) · ",
    `[Configure rules](.pyneat.toml) · `,
    `[Security tab](https://github.com/${process.env.GITHUB_REPOSITORY || "owner/repo"}/security/code-scanning)`,
    "</sub>",
  ].join("\n");
}

// ---------------------------------------------------------------------------
// GitHub API helpers
// ---------------------------------------------------------------------------

/**
 * Post a PR comment with scan results.
 * @param {import('@octokit/rest')} octokit
 * @param {object} context - Probot context
 * @param {object} scanResult - Structured scan result
 * @param {object} options
 */
async function postPRComment(octokit, context, scanResult, options = {}) {
  const { owner, repo } = context.repo();
  const prNumber = context.payload.pull_request.number;

  const body = generatePRBody(scanResult, options);

  return octokit.rest.issues.createComment({
    owner,
    repo,
    issue_number: prNumber,
    body,
  });
}

/**
 * Post a PR review with inline comments.
 * @param {import('@octokit/rest')} octokit
 * @param {object} context - Probot context
 * @param {object} scanResult - Structured scan result
 * @param {object} options
 */
async function postPRReview(octokit, context, scanResult, options = {}) {
  const { owner, repo } = context.repo();
  const prNumber = context.payload.pull_request.number;
  const { showInlineComments = false } = options;

  const criticalCount = scanResult.critical_count || 0;
  const highCount = scanResult.high_count || 0;
  const hasBlockingFindings = criticalCount > 0 || highCount > 0;

  const body = generatePRBody(scanResult, options);

  // Build inline comments for files
  const inlineComments = [];
  if (showInlineComments) {
    const findingsByFile = {};

    for (const finding of scanResult.findings || []) {
      if (!finding.file || !finding.line) continue;
      if (finding.severity !== "critical" && finding.severity !== "high") continue;

      if (!findingsByFile[finding.file]) {
        findingsByFile[finding.file] = [];
      }
      findingsByFile[finding.file].push(finding);
    }

    for (const [file, findings] of Object.entries(findingsByFile)) {
      for (const finding of findings) {
        inlineComments.push({
          path: file,
          line: finding.line,
          body: [
            `## ${finding.severity_emoji || "⚠️"} ${finding.rule_id}: ${finding.message.split("\n")[0]}`,
            "",
            finding.cwe_id ? `**CWE:** [${finding.cwe_id}](https://cwe.mitre.org/)` : "",
            finding.owasp_id ? `**OWASP:** A${finding.owasp_id}` : "",
            finding.cvss_score ? `**CVSS:** ${finding.cvss_score}` : "",
            "",
            finding.snippet ? `\`\`\`\n${(typeof finding.snippet === "string" ? finding.snippet : finding.snippet.text || "").slice(0, 200)}\n\`\`\`` : "",
          ].filter(Boolean).join("\n"),
        });
      }
    }
  }

  const event = hasBlockingFindings ? "REQUEST_CHANGES" : "COMMENT";

  return octokit.rest.pulls.createReview({
    owner,
    repo,
    pull_number: prNumber,
    body,
    event,
    comments: inlineComments,
  });
}

/**
 * Create or update a GitHub Check Run for the scan.
 * @param {import('@octokit/rest')} octokit
 * @param {object} context - Probot context
 * @param {object} scanResult - Structured scan result
 */
async function createCheckRun(octokit, context, scanResult) {
  const { owner, repo } = context.repo();
  const headSha = context.payload.pull_request?.head?.sha || context.payload.check_run?.head_sha;

  if (!headSha) {
    throw new Error("No head SHA found in context");
  }

  const criticalCount = scanResult.critical_count || 0;
  const highCount = scanResult.high_count || 0;
  const totalCount = scanResult.total || 0;

  // Determine conclusion
  let conclusion;
  if (criticalCount > 0) {
    conclusion = "failure";
  } else if (highCount > 0) {
    conclusion = "action_required";
  } else if (totalCount > 0) {
    conclusion = "neutral";
  } else {
    conclusion = "success";
  }

  // Build the output text
  const lines = [
    `# PyNEAT Security Scan Results`,
    ``,
    `| Severity | Count |`,
    `|----------|-------|`,
    `| 🔴 Critical | ${criticalCount} |`,
    `| 🟠 High | ${highCount} |`,
    `| 🟡 Medium | ${scanResult.medium_count || 0} |`,
    `| 🔵 Low | ${scanResult.low_count || 0} |`,
    `| ⚪ Info | ${scanResult.info_count || 0} |`,
    ``,
    `**Total: ${totalCount} finding(s)**`,
    ``,
  ];

  // Add top findings
  const topFindings = (scanResult.findings || []).slice(0, 10);
  if (topFindings.length > 0) {
    lines.push("### Top Findings");
    lines.push("");
    for (const f of topFindings) {
      const emoji = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪" }[f.severity] || "⚪";
      lines.push(`${emoji} \`${f.rule_id}\` at ${f.file}:${f.line}`);
      lines.push(`   ${f.message.split("\n")[0]}`);
      if (f.cwe_id) lines.push(`   CWE: ${f.cwe_id}`);
      lines.push("");
    }
  }

  const output = {
    title: `PyNEAT Scan — ${totalCount} Finding${totalCount !== 1 ? "s" : ""}`,
    summary: [
      `## PyNEAT Security Scan Results`,
      ``,
      criticalCount > 0
        ? `🚨 **${criticalCount} critical** and **${highCount} high** severity issues detected.`
        : totalCount > 0
        ? `✅ Found ${totalCount} issue(s).`
        : `✅ No issues found.`,
      ``,
      `| Severity | Count |`,
      `|----------|-------|`,
      `| 🔴 Critical | ${criticalCount} |`,
      `| 🟠 High | ${highCount} |`,
      `| 🟡 Medium | ${scanResult.medium_count || 0} |`,
      `| 🔵 Low | ${scanResult.low_count || 0} |`,
      ``,
      `Files scanned: ${scanResult.files_scanned || 0} · Duration: ${(scanResult.duration_seconds || 0).toFixed(1)}s`,
    ].join("\n"),
    text: lines.join("\n"),
  };

  // Find existing check run
  const existingCheckRun = await findExistingCheckRun(octokit, owner, repo, headSha);

  if (existingCheckRun) {
    // Update existing check run
    return octokit.rest.checks.update({
      owner,
      repo,
      check_run_id: existingCheckRun.id,
      status: "completed",
      conclusion,
      completed_at: new Date().toISOString(),
      output,
    });
  } else {
    // Create new check run
    return octokit.rest.checks.create({
      owner,
      repo,
      name: "pyneat/scan",
      head_sha: headSha,
      status: "completed",
      conclusion,
      completed_at: new Date().toISOString(),
      output,
      actions: [
        {
          label: "View Full Report",
          description: "View all scan findings in GitHub Code Scanning",
          identifier: "view_report",
        },
        ...(criticalCount > 0 ? [{
          label: "View Critical Issues",
          description: "View critical security issues",
          identifier: "view_critical",
        }] : []),
      ],
    });
  }
}

/**
 * Find an existing pyneat check run for a given SHA.
 */
async function findExistingCheckRun(octokit, owner, repo, headSha) {
  const { data: checkRuns } = await octokit.rest.checks.listForRef({
    owner,
    repo,
    ref: headSha,
    check_name: "pyneat/scan",
    status: "completed",
    per_page: 1,
  });

  return checkRuns.check_runs?.[0] || null;
}

/**
 * Upload SARIF results to GitHub Code Scanning.
 * @param {import('@octokit/rest')} octokit
 * @param {object} context - Probot context
 * @param {string} sarifPath - Path to the SARIF file
 * @param {string} commitSha - The commit SHA to associate with the upload
 */
async function uploadSarif(octokit, context, sarifPath, commitSha) {
  if (!fs.existsSync(sarifPath)) {
    throw new Error(`SARIF file not found: ${sarifPath}`);
  }

  const sarifContent = fs.readFileSync(sarifPath, "utf8");
  const { owner, repo } = context.repo();

  // GitHub Code Scanning SARIF upload API
  const response = await octokit.rest.codeScanning.uploadSarif({
    owner,
    repo,
    sarif: sarifContent,
    commit_sha: commitSha,
    category: "pyneat-scan",
    ref: commitSha,
  });

  return response.data;
}

// ---------------------------------------------------------------------------
// Diff helpers
// ---------------------------------------------------------------------------

/**
 * Get the list of changed files in a PR.
 * @param {import('@octokit/rest')} octokit
 * @param {object} context - Probot context
 */
async function getChangedFiles(octokit, context) {
  const { owner, repo } = context.repo();
  const prNumber = context.payload.pull_request.number;

  const response = await octokit.rest.pulls.listFiles({
    owner,
    repo,
    pull_number: prNumber,
    per_page: 100,
  });

  return response.data.map((f) => ({
    filename: f.filename,
    status: f.status,
    additions: f.additions,
    deletions: f.deletions,
    patch: f.patch,
  }));
}

/**
 * Get the PR diff as a single string.
 * @param {import('@octokit/rest')} octokit
 * @param {object} context - Probot context
 */
async function getPRDiff(octokit, context) {
  const { owner, repo } = context.repo();
  const prNumber = context.payload.pull_request.number;

  const response = await octokit.rest.pulls.get({
    owner,
    repo,
    pull_number: prNumber,
    mediaType: { format: "diff" },
  });

  return response.data;
}

module.exports = {
  generatePRBody,
  generateEmptyBody,
  generateHeader,
  generateSeverityBreakdown,
  generateFindingsSection,
  generateFindingEntry,
  generateSummaryTable,
  generateFooter,
  postPRComment,
  postPRReview,
  createCheckRun,
  uploadSarif,
  getChangedFiles,
  getPRDiff,
};
