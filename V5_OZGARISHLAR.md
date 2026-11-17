# v5: MCP uchun bitta URL (OAuth 2.1) — 4-bosqich

Yoqish: Railway Variables ga `MCP_OAUTH=1` qo‘shing (qolgani v4 dagidek).

## Yangi
- `oauth_server.py`: mijozni ro‘yxatdan o‘tkazish (DCR), PKCE (S256), bir martalik kod (60 s), aylanuvchi refresh token,
  kod/refresh qayta ishlatilsa butun ruxsat bekor qilinadi. Tokenlar bazada faqat xesh.
- Gateway: `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`,
  `/oauth/register`, `/oauth/token`, `/oauth/revoke`; `/mcp` (Bearer) — 401 + `resource_metadata`.
- Panel: `/oauth/authorize` ruxsat sahifasi, Sozlamalar → "Ulangan ilovalar" (bekor qilish).

## Saqlangan
- Eski maxfiy `/mcp/<kalit>` manzillari zaxira sifatida ishlaydi. MCP_OAUTH berilmasa hech narsa o‘zgarmaydi.
- To‘xtatish tugmasi, tasdiq navbati, bloklash Bearer uchun ham amal qiladi.

## Connector manzili
`https://tg-userbot-mcp-production.up.railway.app/mcp`
Ruxsat etilgan qaytish manzillari: claude.ai va claude.com `/api/mcp/auth_callback` (+ localhost). Boshqasi: OAUTH_REDIRECTS.

## Bilish kerak
- Google'dan/Claude'dan qaytganda Strict cookie yuborilmaydi: "Davom etish" va "Ilovaga qaytish" tugmalari bosiladi.
- Brauzer ichidan (boshqa Origin) token so‘rovlari rad etiladi; Claude serverdan chaqiradi.
