/**
 * Diff utilities for parsing PR patches and extracting changed file lists.
 *
 * Copyright (c) 2026 PyNEAT Authors
 * Licensed under GNU AGPL v3.
 */

"use strict";

/**
 * Parse a GitHub patch and extract changed file information.
 * @param {Array<{filename: string, patch?: string, status: string}>} changedFiles
 * @returns {object} Structured diff info
 */
function getChangedFilesFromDiff(changedFiles) {
  const files = [];

  for (const file of changedFiles) {
    const info = {
      filename: file.filename,
      status: file.status,  // added, removed, modified, renamed
      additions: file.additions || 0,
      deletions: file.deletions || 0,
      linesChanged: (file.additions || 0) + (file.deletions || 0),
      hunks: [],
    };

    if (file.patch) {
      info.hunks = parsePatch(file.patch);
    }

    files.push(info);
  }

  return {
    totalFiles: files.length,
    files,
    added: files.filter((f) => f.status === "added").length,
    modified: files.filter((f) => f.status === "modified").length,
    removed: files.filter((f) => f.status === "removed").length,
    renamed: files.filter((f) => f.status === "renamed").length,
  };
}

/**
 * Parse a unified diff patch into hunks.
 * @param {string} patch - The unified diff patch
 * @returns {Array} Parsed hunks
 */
function parsePatch(patch) {
  if (!patch) return [];

  const hunks = [];
  const lines = patch.split("\n");

  let currentHunk = null;
  let hunkHeaderRegex = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

  for (const line of lines) {
    const headerMatch = line.match(hunkHeaderRegex);

    if (headerMatch) {
      if (currentHunk) {
        hunks.push(finalizeHunk(currentHunk));
      }

      currentHunk = {
        oldStart: parseInt(headerMatch[1], 10),
        oldLines: parseInt(headerMatch[2] || "1", 10),
        newStart: parseInt(headerMatch[3], 10),
        newLines: parseInt(headerMatch[4] || "1", 10),
        lines: [],
      };
    } else if (currentHunk) {
      currentHunk.lines.push(line);
    }
  }

  if (currentHunk) {
    hunks.push(finalizeHunk(currentHunk));
  }

  return hunks;
}

/**
 * Finalize a hunk by computing statistics.
 */
function finalizeHunk(hunk) {
  let additions = 0;
  let deletions = 0;
  let context = 0;

  for (const line of hunk.lines) {
    if (line.startsWith("+")) additions++;
    else if (line.startsWith("-")) deletions++;
    else context++;
  }

  return {
    ...hunk,
    additions,
    deletions,
    context,
    totalChanges: additions + deletions,
  };
}

/**
 * Get the changed lines in a specific file from a hunk array.
 * @param {Array} hunks - Parsed hunks from parsePatch
 * @returns {object} Changed line info
 */
function getChangedLines(hunks) {
  const result = {
    additions: [],
    deletions: [],
    modifications: [],
  };

  let newLineCounter = 0;

  for (const hunk of hunks) {
    for (const line of hunk.lines) {
      newLineCounter++;

      if (line.startsWith("+")) {
        result.additions.push({
          content: line.slice(1),
          line: newLineCounter,
          hunk: hunk.oldStart,
        });
      } else if (line.startsWith("-")) {
        result.deletions.push({
          content: line.slice(1),
          line: hunk.oldStart + result.deletions.length,
          hunk: hunk.oldStart,
        });
      }
    }
  }

  return result;
}

/**
 * Filter changed files by language.
 * @param {Array} changedFiles
 * @param {Array<string>} languages
 * @returns {Array} Filtered files
 */
function filterByLanguage(changedFiles, languages) {
  const langExtensions = {
    python: ["py"],
    javascript: ["js", "mjs", "cjs"],
    typescript: ["ts", "tsx", "mts", "cts"],
    go: ["go"],
    java: ["java"],
    rust: ["rs"],
    ruby: ["rb"],
    php: ["php"],
    csharp: ["cs"],
    terraform: ["tf"],
    yaml: ["yaml", "yml"],
    json: ["json"],
  };

  const allowedExtensions = new Set();
  for (const lang of languages) {
    const exts = langExtensions[lang] || [];
    for (const ext of exts) {
      allowedExtensions.add(ext);
    }
  }

  return changedFiles.filter((file) => {
    const ext = file.filename.split(".").pop()?.toLowerCase();
    return allowedExtensions.has(ext);
  });
}

/**
 * Generate a summary of code changes.
 * @param {Array} changedFiles
 * @returns {string} Markdown summary
 */
function generateDiffSummary(changedFiles) {
  const summary = {
    total: changedFiles.length,
    additions: changedFiles.reduce((sum, f) => sum + (f.additions || 0), 0),
    deletions: changedFiles.reduce((sum, f) => sum + (f.deletions || 0), 0),
  };

  const lines = [
    `Changed ${summary.total} file(s): +${summary.additions} / -${summary.deletions}`,
    "",
  ];

  const byLanguage = {};
  for (const file of changedFiles) {
    const ext = file.filename.split(".").pop()?.toLowerCase();
    if (!byLanguage[ext]) byLanguage[ext] = { files: 0, additions: 0, deletions: 0 };
    byLanguage[ext].files++;
    byLanguage[ext].additions += file.additions || 0;
    byLanguage[ext].deletions += file.deletions || 0;
  }

  for (const [ext, stats] of Object.entries(byLanguage)) {
    lines.push(`  \`*.${ext}\`: ${stats.files} file(s), +${stats.additions} / -${stats.deletions}`);
  }

  return lines.join("\n");
}

module.exports = {
  getChangedFilesFromDiff,
  parsePatch,
  getChangedLines,
  filterByLanguage,
  generateDiffSummary,
};
