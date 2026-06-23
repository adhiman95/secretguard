'use strict';

// Public API — for programmatic use
const { scanFile, scanDirectory, scanStaged, scanLastCommit, scanContent } = require('./scanner');
const { PATTERNS, shannonEntropy } = require('./patterns');
const { buildSummary, toJSON, toSARIF } = require('./reporter');
const { auditHistory, installHook, uninstallHook, getCITemplate, isGitRepo } = require('./git');
const { notify, getGitContext } = require('./notify');
const { verifySecret } = require('./verify');

module.exports = {
  scanFile,
  scanDirectory,
  scanStaged,
  scanLastCommit,
  scanContent,
  PATTERNS,
  shannonEntropy,
  buildSummary,
  toJSON,
  toSARIF,
  auditHistory,
  installHook,
  uninstallHook,
  getCITemplate,
  isGitRepo,
  notify,
  getGitContext,
  verifySecret
};
