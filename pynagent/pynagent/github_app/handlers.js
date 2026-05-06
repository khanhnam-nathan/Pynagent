/**
 * Probot event handlers — maps webhook events to business logic.
 *
 * Copyright (c) 2026 PyNEAT Authors
 * Licensed under GNU AGPL v3.
 */

"use strict";

const {
  postPRComment,
  postPRReview,
  createCheckRun,
  uploadSarif,
  getChangedFiles,
} = require("./github_helpers");
const { getChangedFilesFromDiff } = require("./diff_utils");

/**
 * Handle pull_request opened/synchronize/reopened events.
 *
 * This is the main entry point for PR scanning. It:
 * 1. Gets the list of changed files
 * 2. Runs PyNEAT scan on those files
 * 3. Optionally runs AI analysis on high/critical findings
 * 4. Posts PR comments, creates check runs, and uploads SARIF
 */
async function handlePREvent(context, { pyneat, log, aiAnalyzer }) {
  const { pull_request: pr, installation } = context.payload;
  const { owner, repo } = context.repo();

  log.info(
    "Processing PR #%d %s (%s -> %s, SHA: %s)",
    pr.number,
    context.payload.action,
    pr.base.ref,
    pr.head.ref,
    pr.head.sha
  );

  // Rate limit check
  if (installation?.id) {
    const rateLimitKey = `scan:${installation.id}:${pr.head.sha}`;
    // In production with Redis, check and set rate limit
    // For now, proceed
  }

  // Get changed files
  let changedFiles = [];
  try {
    changedFiles = await getChangedFiles(context.octokit, context);
    log.info("PR #%d has %d changed file(s)", pr.number, changedFiles.length);
  } catch (err) {
    log.error("Failed to get changed files: %s", err.message);
  }

  // Run PyNEAT scan
  const scanResult = await runScan(context, changedFiles, { pyneat, log });

  // Post PR comment
  if (process.env.FEATURE_PR_COMMENTS === "true") {
    try {
      await postPRComment(context.octokit, context, scanResult, {
        showSnippets: true,
        maxFindings: 20,
        showFixHints: true,
      });
      log.info("Posted PR comment for #%d", pr.number);
    } catch (err) {
      log.error("Failed to post PR comment: %s", err.message);
    }
  }

  // Create Check Run
  if (process.env.FEATURE_CHECKS_API === "true") {
    try {
      await createCheckRun(context.octokit, context, scanResult);
      log.info("Created/updated check run for PR #%d", pr.number);
    } catch (err) {
      log.error("Failed to create check run: %s", err.message);
    }
  }

  // Upload SARIF
  if (process.env.FEATURE_SARIF_UPLOAD === "true" && scanResult.sarifPath) {
    try {
      await uploadSarif(
        context.octokit,
        context,
        scanResult.sarifPath,
        pr.head.sha
      );
      log.info("Uploaded SARIF for PR #%d", pr.number);
    } catch (err) {
      log.error("Failed to upload SARIF: %s", err.message);
    }
  }

  // Optional: AI analysis on high/critical findings
  if (aiAnalyzer && process.env.ENABLE_AI_ANALYSIS === "true") {
    try {
      const criticalHigh = scanResult.findings?.filter(
        (f) => f.severity === "critical" || f.severity === "high"
      );

      if (criticalHigh?.length > 0) {
        log.info(
          "Running AI analysis on %d critical/high findings for PR #%d",
          criticalHigh.length,
          pr.number
        );

        const enrichedFindings = await aiAnalyzer.analyzeFindings(
          criticalHigh,
          changedFiles,
          pr
        );

        // Update comment with AI-enriched analysis
        if (process.env.FEATURE_PR_COMMENTS === "true") {
          try {
            await postAIReviewComment(context, enrichedFindings);
          } catch (err) {
            log.error("Failed to post AI review comment: %s", err.message);
          }
        }
      }
    } catch (err) {
      log.error("AI analysis failed: %s", err.message);
      // Don't fail the whole scan if AI analysis fails
    }
  }

  return scanResult;
}

/**
 * Run the PyNEAT scan and return structured results.
 */
async function runScan(context, changedFiles, { pyneat, log }) {
  const { repository } = context.payload;
  const repoPath = repository.clone_url;

  // Build the list of files to scan
  let filesToScan = [];

  if (changedFiles.length > 0) {
    // Only scan changed files that match our languages
    const langs = (process.env.PYNEAT_LANGUAGES || "python").split(",");
    filesToScan = changedFiles
      .map((f) => f.filename)
      .filter((file) => {
        const ext = file.split(".").pop()?.toLowerCase();
        const langMap = {
          py: "python",
          js: "javascript",
          ts: "typescript",
          tsx: "typescript",
          go: "go",
          java: "java",
          rs: "rust",
          rb: "ruby",
          php: "php",
          cs: "csharp",
          tf: "terraform",
        };
        return langMap[ext] && langs.includes(langMap[ext]);
      });
  }

  log.debug("Scanning %d file(s)", filesToScan.length);

  // Run the scan via the Python wrapper
  const scanResult = await pyneat.scanDirectoryAsync(
    repository.local_path || repository.full_name,
    filesToScan.length > 0 ? filesToScan : null
  );

  return scanResult;
}

/**
 * Handle check_run events.
 */
async function handleCheckRun(context, { pyneat, log }) {
  const checkRun = context.payload.check_run;

  log.debug("Check run %s: %s", checkRun.name, checkRun.status);

  // Respond to reredquest events (user clicks "Re-run" on the check)
  if (checkRun.status === "in_progress" && checkRun.conclusion === null) {
    log.info("Check run re-requested for %s", checkRun.head_sha);
    // Re-scanning is handled via the queue when the PR event was fired
  }

  return { status: "ok" };
}

/**
 * Handle check_suite events.
 */
async function handleCheckSuite(context, { pyneat, log }) {
  const { check_suite: suite } = context.payload;

  log.debug(
    "Check suite %s: %s (conclusion: %s)",
    suite.id,
    suite.head_sha,
    suite.conclusion
  );

  // Aggregate results across all check runs in the suite
  // This is useful for showing a unified summary across languages

  return { status: "ok" };
}

/**
 * Handle installation.created events.
 */
async function handleInstallation(context, { log }) {
  const { installation } = context.payload;

  log.info(
    "App installed on account %s (id: %d)",
    installation.account.login,
    installation.id
  );

  // In production, you'd:
  // 1. Store the installation in your database
  // 2. Set up any initial configuration
  // 3. Send a welcome message or create an onboarding PR

  return { status: "installed" };
}

/**
 * Post an AI-enriched review comment with false positive analysis.
 */
async function postAIReviewComment(context, enrichedFindings) {
  const { pull_request: pr } = context.payload;
  const { owner, repo } = context.repo();

  const body = [
    "## 🤖 AI Analysis — False Positive Review",
    "",
    "I analyzed the critical and high severity findings using **Qwen/Llama on AMD Cloud**.",
    "",
    "### Findings Assessment",
    "",
    ...enrichedFindings.map((f) => {
      const verdict = f.is_false_positive
        ? "⚠️ **Likely False Positive**"
        : "🚨 **Confirmed True Positive**";

      return [
        `**${f.rule_id}** at ${f.file}:${f.line}`,
        `${verdict}`,
        f.ai_reason ? `> ${f.ai_reason}` : "",
        "",
      ].join("\n");
    }),
    "",
    "> This analysis was generated by AI and should be reviewed manually.",
  ].join("\n");

  await context.octokit.rest.issues.createComment({
    owner,
    repo,
    issue_number: pr.number,
    body,
  });
}

module.exports = {
  handlePREvent,
  handleCheckRun,
  handleCheckSuite,
  handleInstallation,
};
