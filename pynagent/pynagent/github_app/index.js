#!/usr/bin/env node
/**
 * PyNEAT GitHub App — Probot Entry Point
 *
 * An AI-powered GitHub App that scans pull requests for security vulnerabilities
 * using PyNEAT (Rust SAST scanner) and Qwen/Llama on AMD Cloud for AI analysis.
 *
 * Events handled:
 *   - pull_request.opened         → trigger full scan
 *   - pull_request.synchronize   → trigger rescan
 *   - pull_request_review_comment → optional AI chat on comment
 *   - check_run                   → display results in GitHub Checks UI
 *   - check_suite                 → aggregate results across languages
 *   - installation.created        → first-time install
 *   - installation.deleted        → app uninstalled
 *
 * Copyright (c) 2026 PyNEAT Authors
 * Licensed under GNU AGPL v3.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { Probot, run } = require("probot");
const { PyneatWrapper } = require("./pyneat-wrapper");
const { setupBullMQ } = require("./queue");
const {
  handlePREvent,
  handleCheckRun,
  handleCheckSuite,
  handleInstallation,
} = require("./handlers");
const { createLogger } = require("./logger");

// =============================================================================
// App Factory
// =============================================================================

module.exports = (app) => {
  const log = createLogger(app.name);
  const pyneat = new PyneatWrapper({
    cliPath: process.env.PYNEAT_CLI_PATH || "pyneat",
    format: process.env.PYNEAT_FORMAT || "sarif",
    minSeverity: process.env.PYNEAT_MIN_SEVERITY || "low",
    failOn: process.env.PYNEAT_FAIL_ON || "critical",
    languages: (process.env.PYNEAT_LANGUAGES || "python,javascript,typescript,go,java,rust,ruby,php")
      .split(",")
      .map((l) => l.trim()),
    log,
  });

  // Initialize BullMQ queue
  let queue;
  try {
    queue = setupBullMQ();
  } catch (err) {
    log.warn("BullMQ not available, running in single-process mode: %s", err.message);
    queue = null;
  }

  // ---------------------------------------------------------------------------
  // Health check endpoint (Probot handles this via its web server)
  // ---------------------------------------------------------------------------
  app.on("check_run", async (context) => {
    log.info("check_run event for %s", context.payload.check_run.html_url);
    await handleCheckRun(context, { pyneat, log });
  });

  // ---------------------------------------------------------------------------
  // PR opened or updated — enqueue scan job
  // ---------------------------------------------------------------------------
  app.on("pull_request", async (context) => {
    const { action, pull_request: pr } = context.payload;

    if (!["opened", "synchronize", "reopened"].includes(action)) {
      log.debug("Ignoring PR action: %s", action);
      return;
    }

    log.info(
      "PR %s #%d (%s) — enqueueing scan",
      context.payload.repository.full_name,
      pr.number,
      action
    );

    const jobData = {
      owner: context.payload.repository.owner.login,
      repo: context.payload.repository.name,
      prNumber: pr.number,
      installationId: context.payload.installation.id,
      headSha: pr.head.sha,
      baseSha: pr.base.sha,
      changedFiles: [], // populated by handler
      action,
      enqueuedAt: new Date().toISOString(),
    };

    if (queue) {
      // Enqueue for async processing
      await queue.add("scan", jobData, {
        attempts: parseInt(process.env.QUEUE_MAX_RETRIES || "2", 10),
        backoff: { type: "exponential", delay: 5000 },
      });
      log.info("Job %s:%d queued", context.payload.repository.full_name, pr.number);

      // Post immediate "scan started" check run
      await postPendingCheckRun(context, pyneat, log);
    } else {
      // Process synchronously for development / single-process mode
      await handlePREvent(context, { pyneat, log });
    }
  });

  // ---------------------------------------------------------------------------
  // Aggregate results across check runs in a suite
  // ---------------------------------------------------------------------------
  app.on("check_suite", async (context) => {
    const { action, check_suite: suite } = context.payload;

    if (!["completed"].includes(action)) return;

    log.info("check_suite %s for %s", suite.conclusion, suite.head_sha);
    await handleCheckSuite(context, { pyneat, log });
  });

  // ---------------------------------------------------------------------------
  // Installation lifecycle
  // ---------------------------------------------------------------------------
  app.on("installation.created", async (context) => {
    await handleInstallation(context, { log });
  });

  app.on("installation.deleted", async (context) => {
    log.info("App uninstalled from account: %s", context.payload.installation.account.login);
    if (queue) {
      // Clean up jobs for this installation
      try {
        await queue.clean(0, 100, "completed");
        await queue.clean(0, 100, "failed");
        log.info("Cleaned up jobs for installation %d", context.payload.installation.id);
      } catch (err) {
        log.error("Failed to clean up jobs: %s", err.message);
      }
    }
  });

  // ---------------------------------------------------------------------------
  // PR review comment — optional AI chat response
  // ---------------------------------------------------------------------------
  app.on("pull_request_review_comment", async (context) => {
    const { action, comment } = context.payload;

    if (action !== "created") return;

    // Only respond to comments that mention the bot
    const botMention = context.botName;
    if (!comment.body.includes(`@${botMention}`)) {
      log.debug("Ignoring non-mention comment");
      return;
    }

    log.info("Bot mentioned in comment on PR #%d", context.payload.pull_request.number);
    // TODO: wire up AI chat handler for PR comments
    log.info("AI chat on PR comments not yet implemented — coming soon");
  });

  // ---------------------------------------------------------------------------
  // Error handler — log all unhandled errors from this app
  // ---------------------------------------------------------------------------
  app.onError(async (error) => {
    log.error("Uncaught app error: %O", error);
  });

  // ---------------------------------------------------------------------------
  // PR comment on scan completion
  // ---------------------------------------------------------------------------
  app.on("check_run.completed", async (context) => {
    const checkRun = context.payload.check_run;
    if (!checkRun.html_url) return;
    log.debug("Check run %s completed with conclusion: %s", checkRun.name, checkRun.conclusion);
  });
};

// =============================================================================
// Helper: Post a "pending" check run immediately when PR is opened
// =============================================================================

async function postPendingCheckRun(context, pyneat, log) {
  if (process.env.FEATURE_CHECKS_API !== "true") return;

  try {
    const pr = context.payload.pull_request;
    const checkRun = await context.octokit.checks.create({
      owner: context.payload.repository.owner.login,
      repo: context.payload.repository.name,
      name: "pyneat/scan",
      head_sha: pr.head.sha,
      status: "in_progress",
      started_at: new Date().toISOString(),
      output: {
        title: "PyNEAT Scan Starting",
        summary: "PyNEAT security scan has been queued for this pull request.",
        text: `Scan queued at ${new Date().toISOString()}.\n\n"
              + "Powered by [PyNEAT](https://github.com/pyneat/pyneat) "
              + "with AI analysis by Qwen/Llama on AMD Cloud.`,
      },
    });

    log.info("Created pending check run %s for PR #%d", checkRun.data.id, pr.number);
  } catch (err) {
    log.error("Failed to create pending check run: %s", err.message);
  }
}

// =============================================================================
// Main entry point
// =============================================================================

run(module.exports);
