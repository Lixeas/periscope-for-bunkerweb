# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub's private reporting instead: on the repository page, open the **Security** tab and choose **Report a vulnerability**. Include the affected version or commit, the steps to reproduce, and the impact you see.

This is a small project maintained on a best-effort basis. I aim to acknowledge a report within a few days and to publish a fix before any public disclosure.

## Supported versions

Only the latest commit on `main` receives fixes.

## Scope

Periscope is a read-only monitoring tool for BunkerWeb. Reports about its login and session handling, stored credentials (encrypted with `PERISCOPE_SECRET_KEY`), CSRF/origin checks, or anything that would let it write to a BunkerWeb instance are especially welcome.
