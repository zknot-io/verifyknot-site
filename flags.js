// @ts-check
/**
 * verifyknot — site feature flags.
 *
 * This site has NO build step: it is static files served by Cloudflare Pages.
 * A flag is therefore a plain exported constant, and "enabling" a feature is a
 * one-line source edit + deploy. There is no bundler define, no env var, and no
 * runtime config fetch (a runtime fetch would itself be network behaviour we do
 * not want on a page whose entire promise is "the math runs in your browser").
 *
 * ACTIVATION PROCEDURE (portable proof bundle):
 *   1. Set ENABLE_PORTABLE_PROOF_BUNDLE = true below.
 *   2. Commit, then deploy with ./deploy.sh (ships the working dir — check
 *      `git status` first).
 * Rollback is the exact inverse: set it back to false, commit, deploy.
 *
 * Enabling changes NO stored data and requires NO schema migration: the bundle
 * is built in the browser from a record the API already returns today, and the
 * flag gates only whether the UI offers the buttons.
 */

/**
 * Portable HashStamp proof bundle — export (.hashstamp) + offline import.
 * PRODUCTION DEFAULT: false. Staged, not launched.
 *
 * While false: the Download / Open buttons are not rendered, and no
 * proof-bundle code path runs. There is no dead or hidden network behaviour
 * either way — proof-bundle.js contains no fetch/XHR at all, and the ONLY
 * network call in the whole feature is the explicit, user-pressed
 * "Check current status online" button (see checkCurrentStatusOnline).
 */
export const ENABLE_PORTABLE_PROOF_BUNDLE = false;
