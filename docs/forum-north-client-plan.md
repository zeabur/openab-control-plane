# Forum × OCP North Client — Implementation Plan

> **Parked (2026-08-02).** Phase 0 was verified and the plan fired the Stage 3
> extraction as the second north consumer; the forum client itself has not
> been built and no work has landed since 2026-07-09.

Status: proposed · 2026-07-06 · **Phase 0 verified** (see `docs/forum-support-phase0.md`)

Canonical copy also lives in the forum repo:
`forum/docs/forum-ocp-north-client-plan.md`

## Summary

Replace the staff workflow of copying a local `claude …` CLI command with an
in-forum agent panel. Forum acts as an **OCP north client**; execution stays on
the cloud **OpenAB support pod** (Allen / `claude-allen` profile), not on the
staff laptop.

This is **not** a triage council report flow, **not** agent-hub (deprecated), and
**not** a new standalone “Forum Hub” service — only a thin API proxy + UI inside
the forum app.

Reference stack:

- Allen today: OpenAB pod + Discord adapter + support skills (`multi-agent-review-ops`)
- Target: same pod + skills, **forum UI** as north client → `openab-control-plane`

---

## Architecture

```text
┌─────────────────────────────────────┐
│ Forum (north client)                  │
│  · Ticket agent panel (staff-only)    │
│  · /support/api/posts/:id/agent/*   │
└──────────────┬──────────────────────┘
               │ Bearer OABCP_API_KEY (server-side only)
               ▼
┌─────────────────────────────────────┐
│ openab-control-plane                │
│  REST + SSE north API               │
│  gateway /ws south                  │
└──────────────┬──────────────────────┘
               │ GatewayEvent / Reply
               ▼
┌─────────────────────────────────────┐
│ Support pod (Allen profile)         │
│  ghcr.io/openabdev/openab:*-claude   │
│  [gateway] → OCP                    │
│  AGENTS.md + zadmin/zsupport/rag skills│
└─────────────────────────────────────┘
```

| Layer | Owns | Does not own |
|-------|------|----------------|
| Forum | UI, staff auth, OCP proxy | LLM, bot credentials, session store |
| OCP | Sessions, fanout, SSE, gateway | Forum replies, investigation skills |
| OAB pod | Agent execution, tools, skills | North API, forum UX |

Discord on `claude-allen` may remain during migration; forum is a second north
entry.

---

## Identity keys

| Concept | Value |
|---------|--------|
| `trigger_ref` (primary) | `forum:ticket:{linearIdf}` e.g. `forum:ticket:SUP-6035` |
| `trigger_ref` (fallback) | `forum:ticket:post:{postId}` when no Linear idf |
| `mode` | `solo` |
| `quorum_n` | `0` |
| Roster | single bot: OCP `bot_id` for Allen |

Maps to today’s CLI:

```bash
claude --dangerously-skip-permissions --name SUP-6035 "https://zeabur.com/support/ticket/<postId>"
```

| CLI | North client |
|-----|----------------|
| `--name SUP-6035` | `trigger_ref=forum:ticket:SUP-6035` |
| ticket URL argument | opening `POST …/messages` content |
| local terminal output | `GET …/stream` + `GET …/log` |

**Active session rule:** one non-terminal session per `trigger_ref`
(`open` / `deliberating` / `quorum`). After `closed` / `aborted`, opening again
creates a new session with the same `trigger_ref` (history preserved in OCP).

**OCP status (revised at Stage 3 S1, ADR 018):** `POST /v1/sessions` routes
through `controller::execute` and dedupes/supersedes on `trigger_fingerprint`
(#124/#126) — pass `trigger_fingerprint` alongside `trigger_ref` and a repeat
open returns `deduped:true` while a changed fingerprint supersedes the active
session (`superseded:true` + `old_session_id`). Resolving the active session
before open (see §Resolve active session) remains recommended for UX (to show
"reused"), but is no longer a correctness requirement. **Hard rule (forum v1
contract): never post to a `closed`/`aborted` session expecting a reopen —
always open a fresh session after close** (the watchdog anchors its timeout at
`created_at` — no last-activity reset — so a session reopened past that
deadline (default 600s) force-closes on the next ~30s scan, i.e. effectively
immediately for any stale ticket; Stage 3 S13 makes non-solo reopen an
explicit 410).

---

## Environment variables (forum server only)

```bash
OABCP_URL=https://<ocp-host>          # no trailing slash
OABCP_API_KEY=<north bearer>
OABCP_SUPPORT_BOT_ID=<bot_id>         # from OCP POST /v1/bots / seed roster
FORUM_BASE_URL=https://zeabur.com/support   # existing; for ticket URLs
```

Never expose `OABCP_API_KEY` to the browser.

---

## Forum public API (north client proxy)

Base: existing `app/api/posts/[id]/…`. Client calls via `apiPath('/api/posts/…')`.

**Auth:** staff/admin only (same gate as queue “Copy Claude” — `ADMINS` or
extended staff list).

### `GET /api/posts/:id/agent`

Status for this ticket.

**Response 200**

```json
{
  "postId": "674a…",
  "linearIdf": "SUP-6035",
  "triggerRef": "forum:ticket:SUP-6035",
  "activeSession": {
    "sessionId": "ses_…",
    "state": "deliberating",
    "mode": "solo",
    "createdAt": 1782967850544
  },
  "botConnected": true,
  "latestClosedSessionId": "ses_…"
}
```

Implementation: proxy `GET /v1/sessions?trigger_ref=…&limit=10`, pick first
session where `state` ∉ `{closed, aborted}`; optionally `GET /v1/bots` for
`connected`.

---

### `POST /api/posts/:id/agent/start`

Equivalent to paste-and-run CLI.

**Request (optional body)**

```json
{
  "message": "check why SSH fails",
  "forceNew": false
}
```

**Flow**

1. Staff auth
2. Build `triggerRef`, `ticketUrl` (`lib/agent-commands.ts`)
3. Unless `forceNew`: resolve active session
4. If none: `POST /v1/sessions`
5. If `message` or new session: `POST /v1/sessions/:id/messages`
6. Optional: persist `post.agent.lastSessionId` on Mongo `Post`

**Response 200**

```json
{
  "sessionId": "ses_…",
  "triggerRef": "forum:ticket:SUP-6035",
  "reused": true,
  "promptMessageId": "msg_…"
}
```

**Errors:** 401 unauth · 403 non-staff · 404 post · 502 OCP/bot down

---

### `POST /api/posts/:id/agent/messages`

Staff follow-up.

**Request**

```json
{ "content": "check Stripe subscription" }
```

**Flow**

1. Resolve active session; if closed → new session (same `trigger_ref`) + prompt
2. `POST /v1/sessions/:id/messages`

**Response 200**

```json
{
  "sessionId": "ses_…",
  "messageId": "msg_…",
  "sessionReopened": false
}
```

---

### `GET /api/posts/:id/agent/stream`

SSE proxy to OCP.

```http
GET /api/posts/:id/agent/stream?sessionId=ses_…
Accept: text/event-stream
```

Pipe `GET /v1/sessions/:sessionId/stream` with `Authorization: Bearer …`.

**OCP event shape** (each SSE `data:` line):

```json
{
  "type": "message | message_edit | state | verdict | reaction | timeout | thread | roster_add",
  "session_id": "ses_…",
  "payload": {},
  "ts": 1782967850544
}
```

**UI handling**

| `type` | UI |
|--------|-----|
| `message` | New bubble (`payload.author`, `payload.content`) |
| `message_edit` | Update bubble by `payload.message_id` (streaming) |
| `state` | Badge: running / idle (`payload.state`) |
| `verdict` | End of turn; show `payload.text` |
| `timeout` | Watchdog message |

---

### `GET /api/posts/:id/agent/log`

History without live SSE.

Proxy:

```http
GET /v1/session-log?trigger_ref=forum:ticket:SUP-6035&tail_chars=50000
```

Or `GET /v1/sessions/:id/log`. Return `text/plain` or parse for UI.

---

### `GET /api/posts/:id/agent/messages` (optional v1.1)

Structured history via `GET /v1/sessions/:id` → `{ session, messages, reactions }`.

---

## OCP calls (forum `lib/services/ocp-client.ts`)

### Resolve active session (required)

```typescript
async function resolveActiveSession(triggerRef: string) {
  const res = await ocpFetch(
    `/v1/sessions?trigger_ref=${encodeURIComponent(triggerRef)}&limit=10`
  );
  return (res.sessions ?? []).find(
    (s) => !['closed', 'aborted'].includes(s.state)
  ) ?? null;
}
```

Always `encodeURIComponent` on `trigger_ref` (contains `:` and `#` in other refs).

### Open session

```http
POST /v1/sessions

{
  "title": "forum-support",
  "trigger_ref": "forum:ticket:SUP-6035",
  "trigger_fingerprint": "forum:ticket:SUP-6035",
  "mode": "solo",
  "roster": ["<OABCP_SUPPORT_BOT_ID>"],
  "chair_bot": "<OABCP_SUPPORT_BOT_ID>",
  "quorum_n": 0,
  "prompt": "<opening prompt — atomic open-with-prompt, lands at Stage 3 S5>"
}
```

Until Stage 3 S5 lands, `prompt` is ignored (the field exists but api.rs feeds
an empty string) — use the two-call open-then-message flow below and treat the
crash window between the calls as a known S5-closed gap. After S5, prefer the
single atomic call.

### Post message

```http
POST /v1/sessions/{sessionId}/messages

{ "content": "<prompt>" }
```

**Opening prompt template**

```text
Investigate this Zeabur support ticket.

Ticket: {ticketUrl}
Linear: {linearIdf}

Staff request:
{userMessage}

Use your support skills (zsupport, zadmin, zeabur-rag, etc.). Read the full thread
before answering. Do not post a public forum reply unless explicitly asked.
```

Bare start (no staff message) may send only the ticket URL — same as bare CLI.

### Multi-turn (v1)

| Situation | Action |
|-----------|--------|
| Active `deliberating` | `post_message` |
| Session `closed` | New `POST /v1/sessions` + prompt |
| Bot busy | Disable send (v1); queue later |

`solo` closes after one bot turn; next staff message opens a new session; bot
re-fetches ticket via URL (ADR 011 pattern). This new-session-after-close flow
is the **hard v1 contract** (see §OCP status above): solo's in-window reopen
exists (Stage 3 S13 keeps it for solo only), but the watchdog's
`created_at`-anchored timeout force-closes any reopened session that is past
its original deadline — effectively immediately for a stale ticket — so
forum must never depend on reopen.

---

## Infrastructure prerequisites (before forum code)

| Step | Task | Verify |
|------|------|--------|
| 1 | Deploy OCP; `OABCP_API_KEY`, `OABCP_BOTS=allen:chair` | `GET /v1/bots` lists allen |
| 2 | Support pod: Allen image + PVC (`profiles/allen-codex` seed) | Pod RUNNING |
| 3 | Pod `[gateway] url=ws://<ocp>/ws`, `token=<bot token>`, `platform=feishu` | allen `connected: true` |
| 4 | Record `bot_id` → forum `OABCP_SUPPORT_BOT_ID` | |
| 5 | Manual: open session + post message + session-log | Bot replies in log |

---

## Forum implementation checklist

### Phase 0 — Shared library

| File | Purpose |
|------|---------|
| `lib/services/ocp-client.ts` | `ocpFetch`, resolve/open/post, prompt builder, `buildTriggerRef` |
| `lib/services/agent-access.ts` | `requireStaffAgentAccess(user)` |

### Phase 1 — API routes

| File | Methods |
|------|---------|
| `app/api/posts/[id]/agent/route.ts` | `GET` status |
| `app/api/posts/[id]/agent/start/route.ts` | `POST` start |
| `app/api/posts/[id]/agent/messages/route.ts` | `POST` follow-up |
| `app/api/posts/[id]/agent/stream/route.ts` | `GET` SSE proxy |
| `app/api/posts/[id]/agent/log/route.ts` | `GET` log proxy |

### Phase 2 — UI

| File | Purpose |
|------|---------|
| `components/ticket-agent-panel.tsx` | Messages, input, status, EventSource |
| `hooks/use-ticket-agent.ts` | start / send / stream |
| `app/(main)/ticket/[id]/page.tsx` | Render panel for staff |
| `app/(main)/queue/queue-list.tsx` | “Open Agent” (replace or beside Copy Claude) |

Panel is **staff-only**; customer thread unchanged unless staff posts manually or
bot uses zsupport.

### Phase 3 — Optional Mongo

```typescript
agent?: {
  triggerRef?: string;
  lastSessionId?: string;
  updatedAt?: Date;
}
```

OCP remains source of truth; Mongo is convenience for lookups.

### Phase 4 — Tests

- Unit: `buildTriggerRef`, prompt, `resolveActiveSession` (mocked OCP)
- Route: 401/403, happy path start
- Component: SSE `message` / `message_edit` handling

---

## Suggested schedule

| When | Deliverable |
|------|-------------|
| Week 0 | Infrastructure §prerequisites |
| Day 1 | `ocp-client.ts`, `GET /agent`, `GET /agent/log` |
| Day 2 | `POST /agent/start`, `POST /agent/messages` |
| Day 3 | `GET /agent/stream`, read-only panel |
| Day 4 | Live SSE + queue “Open Agent” |
| Day 5 | Dogfood, prompt tuning, error states |

---

## Known limits and follow-ups

| Item | v1 | Later |
|------|-----|-------|
| ~~`POST /v1/sessions` no dedupe~~ resolved: fingerprint dedupe/supersede shipped (#126) | Pass `trigger_fingerprint`; resolve-first kept for UX | Atomic open-with-`prompt` at Stage 3 S5 |
| `solo` one turn per session | New session per follow-up after close | OCP `chat` mode (long-lived) |
| Reply to customer | Manual or bot zsupport | “Post to thread” button in panel |
| Bot disconnected | 502 + UI message | Alerting |

---

## Out of scope

- Triage council / `triage_council` report workflow (ADR 014)
- agent-hub revival
- Local CLI requirement (Copy Claude may remain as fallback temporarily)
- OCP multi-bot council on support tickets (solo only for v1)

---

## Related docs

| Doc | Repo |
|-----|------|
| `lib/agent-commands.ts` | forum — current CLI builders |
| `docs/support-agent-claude.md` | forum — agent playbook snapshot |
| `profiles/allen-codex/` | multi-agent-review-ops — pod seed |
| `docs/control-plane-design.md` | multi-agent-review-ops — north client vision |
| `docs/HANDOFF-control-plane.md` | multi-agent-review-ops — OCP handoff |
| `docs/config-reference.md` | openab-control-plane — env vars |
| `docs/adr/011-conversational-followup.md` | openab-control-plane — stateless multi-turn pattern |