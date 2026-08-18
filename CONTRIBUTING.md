# Contributing

Open a focused change explaining the security decision it affects. Run `npm ci`, `npm run typecheck`, `npm test`, `npm run build`, and `npm audit --audit-level=high`. Add both success and denial tests for authorization, token, or validation changes. Never commit `.env`, `.secrets`, credentials, tokens, production identities, or personal audit data.
