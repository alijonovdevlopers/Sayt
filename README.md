# Social MCP — Telegram + Instagram

The existing Telegram application remains inside `tg_userbot_mcp_railway.zip`.
The Docker build extracts it, overlays `overrides/`, and applies the existing admin
patches. No existing Telegram credentials, database rows, or MCP URLs are replaced.

## Public account flow

- `/register`: choose a username and password, without a Telegram account or invite.
- `/login`: log in using the new credentials; existing configured owner credentials
  and `/login/telegram` continue to work.
- `/`: choose Telegram or Instagram. Each service has its own MCP URL.
- `/telegram`: original dashboard for linked accounts; otherwise Telegram linking.
- `/instagram`: official Instagram Login, connection, MCP key rotation and reply approvals.
- `/account`: site password changes, logout and permanent account deletion.

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
   Instagram Login**. Use the Instagram app ID/secret from the Instagram product.
2. Set Railway service variables securely (never commit secrets):
   - `INSTAGRAM_APP_ID`
   - `INSTAGRAM_APP_SECRET`
   - optional `INSTAGRAM_GRAPH_VERSION` (default `v25.0`)
3. Configure these exact URLs for the current domain:
   - OAuth redirect: `https://tg-userbot-mcp-production.up.railway.app/instagram/callback`
   - Privacy: `https://tg-userbot-mcp-production.up.railway.app/privacy`
   - Data deletion callback: `https://tg-userbot-mcp-production.up.railway.app/instagram/data-deletion`
   - Deauthorization callback: `https://tg-userbot-mcp-production.up.railway.app/instagram/deauthorize`
4. Request `instagram_business_basic`, `instagram_business_manage_messages`,
   and `instagram_business_manage_comments`. Test with app-role/test accounts first.
5. To onboard the public, complete Meta's App Review / Advanced Access requirements,
   any required business verification, and enable Live mode. A site's public
   registration alone does not grant Meta production access.
6. Each end user needs an Instagram Business or Creator account and grants permissions
   in Instagram's own authorization screen. This site never receives their password.

After first successful authorization, a personal `/mcp/instagram/<secret>` URL is
shown once. It can be added to an MCP-capable ChatGPT/Claude client where supported.
No Meta access token is placed in the MCP URL. Refresh is attempted when a valid
long-lived token has fewer than 14 days left; revoked/expired tokens require reconnecting.
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
