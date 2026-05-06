/**
 * Structured logging with Winston.
 *
 * Copyright (c) 2026 PyNEAT Authors
 * Licensed under GNU AGPL v3.
 */

"use strict";

const winston = require("winston");

const { combine, timestamp, printf, colorize, errors } = winston.format;

const logFormat = printf(({ level, message, timestamp, ...metadata }) => {
  let msg = `${timestamp} [${level}]: ${message}`;

  if (Object.keys(metadata).length > 0) {
    msg += ` ${JSON.stringify(metadata)}`;
  }

  return msg;
});

const jsonFormat = printf(({ level, message, timestamp, ...metadata }) => {
  return JSON.stringify({
    level,
    message,
    timestamp,
    ...metadata,
  });
});

function createLogger(name) {
  const logLevel = process.env.LOG_LEVEL || "info";
  const logFormat_ = process.env.LOG_FORMAT || "json";

  const formats = [
    timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
    errors({ stack: true }),
  ];

  if (logFormat_ === "json") {
    formats.push(jsonFormat);
  } else {
    formats.push(colorize());
    formats.push(logFormat);
  }

  return winston.createLogger({
    level: logLevel,
    format: combine(...formats),
    defaultMeta: { service: name || "pyneat-github-app" },
    transports: [
      new winston.transports.Console(),
    ],
  });
}

module.exports = { createLogger };
