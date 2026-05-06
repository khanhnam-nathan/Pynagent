/**
 * BullMQ job queue setup for async scan processing.
 *
 * Copyright (c) 2026 PyNEAT Authors
 * Licensed under GNU AGPL v3.
 */

"use strict";

const { Queue, Worker } = require("bullmq");
const IORedis = require("ioredis");
const { createLogger } = require("./logger");
const { handlePREvent } = require("./handlers");

let connection = null;
let scanQueue = null;
let notifyQueue = null;
let scanWorker = null;
let notifyWorker = null;

/**
 * Set up BullMQ queues and workers.
 *
 * @param {object} options
 * @param {object} options.pyneat - PyNEAT CLI wrapper instance
 * @param {object} options.log - Winston logger
 * @returns {{ scanQueue: Queue, notifyQueue: Queue }}
 */
function setupBullMQ(options = {}) {
  const log = options.log || createLogger("queue");

  const redisUrl = process.env.REDIS_URL || "redis://localhost:6379";
  const useTls = process.env.REDIS_TLS === "true";

  // Create Redis connection
  connection = new IORedis(redisUrl, {
    maxRetriesPerRequest: null,  // Required for BullMQ
    enableReadyCheck: false,
    tls: useTls ? {} : undefined,
    retryStrategy: (times) => {
      if (times > 3) {
        log.error("Redis connection failed after 3 retries");
        return null; // Stop retrying
      }
      return Math.min(times * 200, 2000);
    },
  });

  connection.on("error", (err) => {
    log.error("Redis connection error: %s", err.message);
  });

  connection.on("connect", () => {
    log.info("Connected to Redis at %s", redisUrl);
  });

  // Create queues
  scanQueue = new Queue("pyneat-scan", {
    connection,
    defaultJobOptions: {
      attempts: parseInt(process.env.QUEUE_MAX_RETRIES || "2", 10),
      backoff: {
        type: "exponential",
        delay: 5000,
      },
      removeOnComplete: {
        count: 100,  // Keep last 100 completed jobs
        age: 60 * 60 * 24,  // Or jobs less than 24 hours old
      },
      removeOnFail: {
        count: 500,  // Keep more failed jobs for debugging
        age: 60 * 60 * 24 * 7,  // Keep for 7 days
      },
    },
  });

  notifyQueue = new Queue("pyneat-notify", {
    connection,
    defaultJobOptions: {
      attempts: 3,
      backoff: { type: "exponential", delay: 3000 },
      removeOnComplete: { count: 50 },
      removeOnFail: { count: 100 },
    },
  });

  // Create scan worker
  scanWorker = new Worker(
    "pyneat-scan",
    async (job) => {
      const {
        owner,
        repo,
        prNumber,
        installationId,
        headSha,
        changedFiles,
        action,
      } = job.data;

      log.info(
        "Processing scan job %s for %s/%s PR #%d (SHA: %s)",
        job.id,
        owner,
        repo,
        prNumber,
        headSha
      );

      await job.updateProgress(10);

      // The actual scan is handled in handlers.js
      // Here we just log and update progress
      await job.updateProgress(50);

      return { status: "completed", jobId: job.id };
    },
    {
      connection,
      concurrency: parseInt(process.env.QUEUE_CONCURRENCY || "3", 10),
    }
  );

  scanWorker.on("completed", (job, result) => {
    log.info("Job %s completed: %O", job.id, result);
  });

  scanWorker.on("failed", (job, err) => {
    log.error("Job %s failed: %s", job?.id, err.message);
  });

  scanWorker.on("progress", (job, progress) => {
    log.debug("Job %s progress: %s%%", job.id, progress);
  });

  // Create notification worker
  notifyWorker = new Worker(
    "pyneat-notify",
    async (job) => {
      const { channel, payload } = job.data;

      log.info("Sending notification via %s for job %s", channel, job.id);

      // Notifications are handled via the webhook server
      // This worker is for retrying failed notifications

      return { status: "sent", channel };
    },
    {
      connection,
      concurrency: 5,
    }
  );

  log.info("BullMQ queues initialized");
  log.info("  Scan queue: pyneat-scan (concurrency: %s)", process.env.QUEUE_CONCURRENCY || "3");
  log.info("  Notify queue: pyneat-notify");

  return { scanQueue, notifyQueue };
}

/**
 * Enqueue a scan job.
 * @param {object} jobData - Job data matching the shape in index.js
 */
async function enqueueScan(jobData) {
  if (!scanQueue) {
    throw new Error("BullMQ not initialized. Call setupBullMQ() first.");
  }

  const job = await scanQueue.add("scan", jobData, {
    jobId: `scan-${jobData.owner}-${jobData.repo}-${jobData.prNumber}-${jobData.headSha}`,
  });

  return job;
}

/**
 * Enqueue a notification job.
 * @param {string} channel - slack | discord | email
 * @param {object} payload - Notification payload
 */
async function enqueueNotification(channel, payload) {
  if (!notifyQueue) {
    throw new Error("BullMQ not initialized. Call setupBullMQ() first.");
  }

  return notifyQueue.add("notify", { channel, payload }, {
    jobId: `notify-${channel}-${Date.now()}`,
  });
}

/**
 * Gracefully shut down all queue connections.
 */
async function shutdownQueues() {
  const log = createLogger("queue");

  log.info("Shutting down BullMQ queues...");

  if (scanWorker) await scanWorker.close();
  if (notifyWorker) await notifyWorker.close();
  if (scanQueue) await scanQueue.close();
  if (notifyQueue) await notifyQueue.close();
  if (connection) await connection.quit();

  log.info("All queue connections closed");
}

module.exports = {
  setupBullMQ,
  enqueueScan,
  enqueueNotification,
  shutdownQueues,
};
