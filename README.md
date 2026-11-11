# Social MCP — Telegram + Instagram

The existing Telegram application remains inside `tg_userbot_mcp_railway.zip`.
The Docker build extracts it, overlays `overrides/`, and applies the existing admin
patches. No existing Telegram credentials, database rows, or MCP URLs are replaced.

## Public account flow

- `/register`: choose a username and password, without a Telegram account or invite.
- `/login`: log in using the new credentials; existing configured owner credentials
  and `/login/telegram` continue to work.
- `/`: choose Telegram or Instagram, and view unread messages/announcements from Admin. Each service has its own MCP URL.
- `/telegram`: original dashboard for linked accounts; otherwise Telegram linking.
- `/instagram`: official Meta Unified Login / Instagram Login with direct 303 OAuth redirect, connection, MCP key rotation and reply approvals.
- `/messages`: view personal messages and broadcast announcements sent by the Administrator, and mark them as read.
- `/account`: site password changes, logout and permanent account deletion.
- `/admin`: platform statistics, user management (blocking/unblocking), personal and broadcast in-app messaging, and one-time Telegram invites.

Blocked accounts cannot access the site or MCP endpoints; when visiting the site or attempting to log in, blocked users see the restriction screen (`Siz saytga kira olmaysiz, iltimos adminga murojaat qiling`) with the Administrator's Telegram link (`@alijonov_aex` under `Admin`).

New site accounts use the existing user identity and separate scrypt password hashes.
Telegram linking adds its verified Telegram identity and separate Telegram PIN to
that same user. Instagram tokens and pending reply text are Fernet-encrypted using
the existing ENC_KEY. All resource, action and token queries are scoped by user ID.
Instagram and Telegram capability tokens are separate and not interchangeable.

## Instagram production setup (required)

The code is implemented, but an Instagram app and Meta approval cannot be created
by source code. Until the following variables exist the UI shows a clear setup
message, without a fake Instagram login button.

1. In Meta for Developers create/configure an app supporting **Instagram API with
   Unified Login**. Create a Facebook Login for Business configuration with Instagram
   assets. Use the Meta app ID and secret from App settings → Basic.
2. Set Railway service variables securely (never commit secrets):
   - `INSTAGRAM_APP_ID`
   - `INSTAGRAM_APP_SECRET` (server secret; enter securely in Railway)
   - `INSTAGRAM_CONFIG_ID` (the selected Facebook Login for Business configuration)
   - `INSTAGRAM_LOGIN_MODE=unified` (default)
   - `INSTAGRAM_TOKEN_LIFETIME=never` only when the configuration says Never
   - optional `INSTAGRAM_GRAPH_VERSION` (default `v25.0`)
3. Configure these exact URLs for the current domain:
   - OAuth redirect: `https://tg-userbot-mcp-production.up.railway.app/instagram/callback`
   - Privacy: `https://tg-userbot-mcp-production.up.railway.app/privacy`
   - Data deletion callback: `https://tg-userbot-mcp-production.up.railway.app/instagram/data-deletion`
   - Deauthorization callback: `https://tg-userbot-mcp-production.up.railway.app/instagram/deauthorize`
4. Configure `instagram_basic`, `instagram_manage_messages`,
   and `instagram_manage_comments` in the configuration. Test with app-role/test accounts first.
5. To onboard the public, complete Meta's App Review / Advanced Access requirements,
   any required business verification, and enable Live mode. A site's public
   registration alone does not grant Meta production access.
6. Each end user needs an Instagram Business or Creator account and grants permissions
   in Instagram's own authorization screen. This site never receives their password.

After first successful authorization, a personal `/mcp/instagram/<secret>` URL is
shown once. It can be added to an MCP-capable ChatGPT/Claude client where supported.
No Meta access token is placed in the MCP URL. Unified Login exchanges the code once
on graph.facebook.com and discovers assigned Instagram accounts with pagination.
One selected account is supported per site account; reconnect preserves that account.
If several new accounts are shared, the user must repeat consent with one account.
System-user IDs are never used as Instagram IDs. Provider metadata is stored per
connection; existing legacy Instagram tokens keep their original API host/refresh.
Unified tokens never use Instagram Login refresh endpoints. A zero expiry means
the explicitly configured Never lifetime; Meta may still revoke access. Positive
expiry values are honored, and expired/revoked tokens require reconnection.
For an existing legacy app only, set INSTAGRAM_LOGIN_MODE=instagram and its Instagram
product credentials. Do not mix parent Meta and Instagram product credentials.
OAuth state is single-use, expires in 10 minutes, and is bound to a still-valid site
session. A short-lived Lax OAuth cookie supports the cross-site return; the main
session remains Strict.

## Instagram tools

`instagram_profile`, `instagram_posts`, `instagram_comments`,
`instagram_conversations`, `instagram_messages`, `instagram_prepare_reply`, and
`instagram_prepare_comment_reply`.

Replies are prepared as encrypted pending actions and sent only after the owner
confirms the exact text and target on the site. Meta enforces messaging permissions
and reply windows; HUMAN_AGENT is never used to extend automation permissions.
Previously listed, tenant-owned resource IDs are required for follow-up operations.
Pagination exposes cursors, never token-bearing next URLs. Uncertain writes are not
retried automatically. Disconnecting revokes the local MCP key and erases Instagram
connection data and pending actions. Signed Meta deauthorization/deletion requests
are verified with HMAC-SHA256. Data deletion receipts are retained for 30 days.

This release does not include autonomous comment-to-DM campaigns, a flow builder,
or a public Instagram App Review approval. Its scope is public website accounts,
platform linking and personal MCP access.

## Validation

Run the existing Telegram regression suite plus `test_social.py` from a clean
extraction, after applying the same overlays and patches as the Docker build:

```sh
python -m zipfile -e tg_userbot_mcp_railway.zip /tmp/social-mcp-test
cp -R overrides/. /tmp/social-mcp-test/tg_userbot_mcp/
cd /tmp/social-mcp-test/tg_userbot_mcp
python first_admin_patch.py
python admin_login_patch.py
python -m pip install -r requirements.lock.txt
python check.py
python -m unittest discover -q
```

The application uses the existing persistent `/data` volume. New tables are additive;
keep `ENC_KEY`, `MCP_SECRET`, and existing owner variables unchanged. A single worker
is required, as in the original server.

Unified Login request-contract tests use mocked Meta responses. Real consent and
API access still require an App Secret, an app-role Instagram account, and a live
end-to-end test. MCP reads fetch data on demand; this version does not ingest
Instagram webhook events or claim Meta App Review approval.
