/**
 * dsh-session-http — a JSON HTTP gateway over ordinary DSH Sessions.
 *
 * It exposes four operations on an isolated HTTP listener so an external
 * program (a script, a chat bridge, a WeChat relay) can drive the same
 * Sessions the Web UI shows:
 *
 *   GET  /workspaces                 every registered Workspace
 *   GET  /sessions                   every visible Session + its Workspace
 *   GET  /sessions/{id}              one Session's detail
 *   POST /sessions                   create or adopt one Session
 *   POST /sessions/{id}/messages     deliver a user message, wait, return the answer
 *
 * A delivered message is an ordinary human `user/message`, so it appears in
 * the GUI conversation exactly as if it had been typed there.
 *
 * Authentication goes through the DSH credential seam: the config carries a
 * *reference* (an environment-variable-style name), never the secret, and the
 * value is resolved once per request. That is what lets a rotation reach the
 * next call with no restart, and it means the key may live either in the
 * process environment or in the provider-managed `$DSH_HOME/.credentials.yaml`
 * — whichever the deployment prefers. An unconfigured reference fails the
 * request with 503 rather than refusing to load the whole composition.
 *
 * This file intentionally imports nothing but node builtins. The plugin is
 * installed into a DSH profile as a `@local/*` junction pointing outside the
 * checkout, so a bare `@deepseek-ai/*` specifier would not resolve from here.
 * Everything it needs arrives through the Cordis context instead.
 */

import { createHash, randomUUID, timingSafeEqual } from 'node:crypto'

/** Cordis function-plugin name. */
export const name = 'session-http'

/**
 * Host services required before any route can register.
 *
 * `sessions` is listed because the gateway reads `ctx.sessionController` — a
 * service read outside `inject` throws in Cordis once the fiber walk reaches
 * the root, so an undeclared read is a load-time crash, not a soft failure.
 */
export const inject = [
  'webServer',
  'sessionController',
  'workspaceRegistry',
  'sessions',
  'credentials',
  'permissionPresets',
  'approval',
]

const DEFAULT_MAX_BODY_BYTES = 1024 * 1024
const DEFAULT_TURN_TIMEOUT_MS = 10 * 60 * 1000
const DEFAULT_SECRET_ENV = 'DSH_SESSION_HTTP_KEY'

/**
 * Approval policy applied to Sessions this gateway creates.
 *
 * `ask` dispatches the composed answerer chain, and with a Web UI open that
 * means a modal prompt. An API caller has no window to answer in, so its turn
 * would block until the HTTP request timed out. `never` does not mean "allow":
 * it means "never ask, decide `rejected` without dispatching any answerer", so
 * a confined Session keeps its sandbox and any one-shot escalation request is
 * simply denied — the agent is told, adapts, and the turn finishes.
 *
 * A deployment that does want interactive prompts can set `ask` here or per
 * request.
 */
const DEFAULT_APPROVAL_POLICY = 'never'
const DEFAULT_RELAY_APPROVAL_TIMEOUT_MS = 2 * 60 * 1000

/** The approval policies the harness defines. */
const APPROVAL_POLICIES = ['ask', 'never']

/** Decisions a caller may return for one relayed approval. */
const RELAY_DECISIONS = new Map([
  ['allow', 'allowed-once'],
  ['allowed-once', 'allowed-once'],
  ['deny', 'rejected'],
  ['rejected', 'rejected'],
])

/** A CredentialRef is a POSIX-style environment-variable name. */
const CREDENTIAL_REF_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/

/**
 * A signal that is never aborted, for the read-only list/inspect calls this
 * gateway makes on behalf of a request it has already committed to answer.
 */
const NO_ABORT = new AbortController().signal

/**
 * Validate the deployment config.
 *
 * Not using Schemastery: this plugin is loaded from outside the checkout, so
 * a bare `@deepseek-ai/schemastery` specifier would fail to resolve.
 *
 * @param config - raw config supplied by the loader entry.
 * @returns the normalized config.
 * @throws when a required value is missing or malformed.
 */
function resolveConfig(config) {
  if (config === null || typeof config !== 'object') {
    throw new Error('session-http: config must be an object')
  }
  const secretEnv = config.secretEnv ?? DEFAULT_SECRET_ENV
  if (typeof secretEnv !== 'string' || !CREDENTIAL_REF_PATTERN.test(secretEnv)) {
    throw new Error(
      'session-http: config.secretEnv must be a POSIX-style environment-variable name '
      + '(the credential reference the gateway resolves on every request)',
    )
  }
  const maxBodyBytes = config.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1) {
    throw new Error('session-http: config.maxBodyBytes must be a positive safe integer')
  }
  const turnTimeoutMs = config.turnTimeoutMs ?? DEFAULT_TURN_TIMEOUT_MS
  if (!Number.isSafeInteger(turnTimeoutMs) || turnTimeoutMs < 1) {
    throw new Error('session-http: config.turnTimeoutMs must be a positive safe integer')
  }
  const turnErrorText = config.turnErrorText ?? 'Agent turn did not complete.'
  const defaultAgentPreset = config.defaultAgentPreset
  const permissionPreset = config.permissionPreset
  if (permissionPreset !== undefined
    && (typeof permissionPreset !== 'string' || permissionPreset.trim() === '')) {
    throw new Error('session-http: config.permissionPreset must be a non-empty string when provided')
  }
  const approvalPolicy = config.approvalPolicy ?? DEFAULT_APPROVAL_POLICY
  if (!APPROVAL_POLICIES.includes(approvalPolicy)) {
    throw new Error(`session-http: config.approvalPolicy must be one of ${APPROVAL_POLICIES.join(', ')}`)
  }
  const relayApprovals = config.relayApprovals ?? true
  if (typeof relayApprovals !== 'boolean') {
    throw new Error('session-http: config.relayApprovals must be a boolean')
  }
  const approvalTimeoutMs = config.approvalTimeoutMs ?? DEFAULT_RELAY_APPROVAL_TIMEOUT_MS
  if (!Number.isSafeInteger(approvalTimeoutMs) || approvalTimeoutMs < 1) {
    throw new Error('session-http: config.approvalTimeoutMs must be a positive safe integer')
  }
  // Relaying needs the waterfall to run, and `never` short-circuits before it.
  // So a relay deployment asks, and the answerer — not the caller's absence —
  // is what decides.
  const effectiveApprovalPolicy = relayApprovals && config.approvalPolicy === undefined
    ? 'ask'
    : approvalPolicy
  return {
    secretEnv,
    maxBodyBytes,
    turnTimeoutMs,
    turnErrorText,
    approvalPolicy: effectiveApprovalPolicy,
    relayApprovals,
    approvalTimeoutMs,
    ...(typeof defaultAgentPreset === 'string' && defaultAgentPreset !== ''
      ? { defaultAgentPreset }
      : {}),
    ...(permissionPreset === undefined ? {} : { permissionPreset }),
  }
}

/**
 * Compare two secrets without leaking length or prefix through timing.
 * @param actual - caller-supplied value, of any length.
 * @param expected - configured secret.
 * @returns whether they are equal.
 */
function secretMatches(actual, expected) {
  if (typeof actual !== 'string') return false
  const a = createHash('sha256').update(actual).digest()
  const b = createHash('sha256').update(expected).digest()
  return timingSafeEqual(a, b)
}

/**
 * Write one JSON response.
 * @param res - response owner.
 * @param status - HTTP status code.
 * @param value - JSON-serializable body.
 */
function sendJson(res, status, value) {
  // A listener failure after the response is committed must not attempt a
  // second write: node would raise ERR_STREAM_WRITE_AFTER_END instead of
  // reporting the original problem.
  if (res.writableEnded) return
  const body = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8')
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(body.length),
    'cache-control': 'no-store',
  })
  res.end(body)
}

/**
 * Write one JSON error response.
 * @param res - response owner.
 * @param status - HTTP status code.
 * @param code - stable machine-readable error code.
 * @param message - human-readable explanation.
 */
function sendError(res, status, code, message) {
  sendJson(res, status, { error: { code, message } })
}

/**
 * Decode one regex-captured path segment.
 * @param raw - the captured segment.
 * @returns the decoded value, or the raw text when it is not valid percent-encoding.
 */
function decodeSegment(raw) {
  try {
    return decodeURIComponent(raw)
  } catch {
    return raw
  }
}

/**
 * Read and parse a bounded JSON request body.
 * @param req - request owner.
 * @param maxBodyBytes - raw byte ceiling.
 * @returns the parsed JSON value.
 * @throws a tagged error for an oversized or malformed body.
 */
async function readJsonBody(req, maxBodyBytes) {
  const chunks = []
  let size = 0
  for await (const chunk of req) {
    size += chunk.length
    if (size > maxBodyBytes) {
      const error = new Error(`request body exceeds maxBodyBytes (${maxBodyBytes})`)
      error.code = 'too-large'
      throw error
    }
    chunks.push(chunk)
  }
  const raw = Buffer.concat(chunks).toString('utf8')
  if (raw.trim() === '') return {}
  try {
    return JSON.parse(raw)
  } catch {
    const error = new Error('request body is not valid JSON')
    error.code = 'bad-json'
    throw error
  }
}

/**
 * Build one frozen human user message.
 *
 * Mirrors the checkout's `createUserMessage`: a fresh stable id, role `user`,
 * and a `{ kind: 'user' }` source. That source is what makes the message a
 * direct human prompt rather than synthetic injected context, so the GUI
 * renders it as a real user turn.
 *
 * @param text - the caller's message text.
 * @returns an immutable user message.
 */
function createHumanMessage(text) {
  const message = {
    id: randomUUID(),
    role: 'user',
    content: [{ type: 'text', text }],
    source: { kind: 'user' },
  }
  const deepFreeze = (value) => {
    if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
      Object.freeze(value)
      for (const child of Object.values(value)) deepFreeze(child)
    }
    return value
  }
  return deepFreeze(message)
}

/**
 * Extract the assistant text a turn produced.
 * @param parts - text fragments collected from that turn's assistant messages.
 * @returns the joined text.
 */
function joinAssistantText(parts) {
  return parts.filter(part => part.trim() !== '').join('\n\n')
}

/**
 * Validate a caller's answers against the questions that were actually asked.
 *
 * The asker validates the answer shape, but a label it never offered would be
 * a choice put in the model's mouth — so this check happens where the offered
 * options are still known, rather than surfacing later as a confusing tool
 * failure. An empty list is legal: the interactive UI offers Skip, so
 * answering nothing is a real outcome, not a malformed request.
 *
 * @param answers - the caller's raw `answers` value.
 * @param questions - the questions the parked turn asked.
 * @returns the accepted answers, or a message explaining the rejection.
 */
function validateQuestionAnswers(answers, questions) {
  if (!Array.isArray(answers)) return { error: 'answers must be an array.' }
  const byId = new Map(questions.map(question => [question.id, question]))
  const accepted = []
  const seen = new Set()
  for (const item of answers) {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) {
      return { error: 'each answer must be an object carrying an id.' }
    }
    if (typeof item.id !== 'string' || !byId.has(item.id)) {
      return { error: `answer id ${JSON.stringify(item.id)} is not one of the asked questions.` }
    }
    if (seen.has(item.id)) return { error: `question "${item.id}" was answered twice.` }
    seen.add(item.id)
    const question = byId.get(item.id)
    const selected = item.selected ?? []
    if (!Array.isArray(selected) || selected.some(label => typeof label !== 'string')) {
      return { error: `selected for question "${item.id}" must be an array of option labels.` }
    }
    const offered = question.options ?? []
    for (const label of selected) {
      if (!offered.some(option => option.label === label)) {
        return { error: `question "${item.id}" was not offered the option ${JSON.stringify(label)}.` }
      }
    }
    if (question.multiSelect !== true && selected.length > 1) {
      return { error: `question "${item.id}" is single-select.` }
    }
    if (item.custom !== undefined && typeof item.custom !== 'string') {
      return { error: `custom for question "${item.id}" must be a string.` }
    }
    accepted.push({
      id: item.id,
      selected: [...selected],
      ...(item.custom === undefined ? {} : { custom: item.custom }),
    })
  }
  return { answers: accepted }
}

/**
 * Wait for one delivered message to be claimed by a turn and for that turn to
 * close, collecting the assistant text on the way.
 *
 * `followup()` returns no receipt, so the correlation is done on the message
 * id we minted: `agent/inbox/claimed` carries the turn that claimed it, and
 * `turn/end` carries the turn it closes. Waiting on the whole-agent
 * `whenIdle()` instead would span every queued turn and could hand one
 * caller another caller's answer.
 *
 * @param ctx - Host context carrying the event bus.
 * @param sessionId - target Session identity.
 * @param messageId - identity of the message we just delivered.
 * @param timeoutMs - ceiling on the wait.
 * @returns a discriminated outcome describing how the wait ended.
 */
function waitForTurn(ctx, sessionId, messageId, timeoutMs) {
  return new Promise((resolve) => {
    let turn
    let settled = false
    const parts = []
    const disposers = []
    let timer

    const finish = (outcome) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      for (const dispose of disposers) {
        try {
          dispose()
        } catch {
          // A listener already torn down by plugin unload; nothing to do.
        }
      }
      resolve(outcome)
    }

    const listen = (event, listener) => {
      const dispose = ctx.on(event, listener)
      if (typeof dispose === 'function') disposers.push(dispose)
    }

    timer = setTimeout(() => finish({ kind: 'timeout' }), timeoutMs)
    // Do not hold the process open for a pending HTTP wait.
    if (typeof timer.unref === 'function') timer.unref()

    listen('agent/inbox/claimed', (payload) => {
      if (payload?.agent?.id !== sessionId) return
      if (payload?.message?.id !== messageId) return
      turn = payload.turn
    })

    listen('agent/inbox/discarded', (payload) => {
      if (payload?.message?.id !== messageId) return
      finish({ kind: 'discarded' })
    })

    listen('session/event', (session, event) => {
      if (session?.id !== sessionId) return
      if (event?.type === 'assistant/message') {
        // Ignore turns that are not ours: another caller's queued work may run first.
        if (turn === undefined || event.data.turn !== turn) return
        for (const block of event.data.message?.content ?? []) {
          if (block?.type === 'text' && typeof block.text === 'string') parts.push(block.text)
        }
        return
      }
      if (event?.type !== 'turn/end') return
      if (turn === undefined || event.data.turn !== turn) return
      finish({ kind: 'ended', turn, reason: event.data.reason, text: joinAssistantText(parts) })
    })
  })
}

/**
 * Describe one turn-end reason for a caller that only sees JSON.
 * @param reason - the durable TurnEndReason.
 * @returns a compact code and message.
 */
function describeTurnEnd(reason) {
  const kind = reason?.kind ?? 'unknown'
  if (kind === 'completed') return { code: 'completed', message: 'Turn completed.' }
  if (kind === 'aborted') return { code: 'aborted', message: `Turn was aborted (${reason?.reason?.kind ?? 'unknown'}).` }
  if (kind === 'error') return { code: 'error', message: reason?.error?.message ?? 'Turn failed.' }
  if (kind === 'max-tokens') return { code: 'max-tokens', message: 'Turn stopped at the output-token cap.' }
  if (kind === 'blocked') return { code: 'blocked', message: 'Turn was blocked.' }
  if (kind === 'interrupted') return { code: 'interrupted', message: 'Turn was interrupted.' }
  return { code: String(kind), message: `Turn ended with reason "${String(kind)}".` }
}

/** Read the caller's API key from the request headers. */
function apiKeyOf(req) {
  const value = req.headers['x-api-key']
  return Array.isArray(value) ? value[0] : value
}

/** Whether the request declares a JSON body. */
function declaresJson(req) {
  const value = req.headers['content-type']
  const contentType = (Array.isArray(value) ? value[0] : value) ?? ''
  return contentType.toLowerCase().split(';')[0].trim() === 'application/json'
}

/**
 * Read the durable title off a list row.
 *
 * `SessionSummary` has no `title` member: the title is a Session projection,
 * so it arrives inside `projections.values.title` and stays absent whenever
 * the projection cache holds no value for that row.
 *
 * @param item - one SessionSummary.
 * @returns the durable title, or null when none is projected.
 */
function titleOfSummary(item) {
  const projected = item?.projections?.values?.title
  return typeof projected === 'string' && projected !== '' ? projected : null
}

/**
 * Derive the label the GUI sidebar shows for a Session.
 *
 * Mirrors the client's own fallback chain — durable title, then the project
 * directory's basename, then the raw Session id — so a caller rendering a
 * picker shows the same words the sidebar does.
 *
 * @param title - durable title, or null.
 * @param cwd - the Session working directory, when known.
 * @param sessionId - the identity used as the last resort.
 * @returns the display label.
 */
function displayTitleOf(title, cwd, sessionId) {
  if (title !== null) return title
  if (typeof cwd === 'string' && cwd !== '') {
    const base = cwd.replace(/[\\/]+$/, '').split(/[\\/]/).pop()
    if (base !== undefined && base !== '') return base
  }
  return sessionId
}

/**
 * Build the lookups the HTTP responses need: which Workspace owns each
 * Session, and which Sessions this deployment has archived.
 *
 * Archiving never touches Workspace accounting — an archived Session keeps
 * its ledger slot — so the archive set is a separate fact, and it is what
 * hides a Session from every grouping surface. The GUI filters on it, and so
 * does this gateway.
 *
 * @param registry - the Workspace registry.
 * @returns ordered Workspaces plus the owner and archive lookups.
 */
function workspaceIndex(registry) {
  const bySession = new Map()
  const rows = registry.list()
  for (const workspace of rows) {
    for (const sessionId of workspace.sessionIds) {
      bySession.set(sessionId, workspace)
    }
  }
  const archived = new Set(registry.archivedSessionIds ?? [])
  return { rows, bySession, archived }
}

/**
 * Apply the gateway's permission posture to a freshly created Session.
 *
 * An API caller has no window to answer an approval prompt: with a Web UI open
 * an `ask` policy raises a modal and the turn blocks until someone clicks,
 * which for an unattended bridge means blocking until the HTTP request times
 * out. The default here is therefore `never`, which does not grant anything —
 * it decides `rejected` without dispatching an answerer. The Session keeps
 * whatever sandbox its preset gives it, and a one-shot escalation request is
 * denied deterministically so the agent is told and can adapt.
 *
 * `permissionPresets.set` is the initialization path the harness intends: it
 * writes the sandbox and approval knobs directly, with no "policy changed"
 * notice in the transcript.
 *
 * @param ctx - Host context carrying the permission and approval services.
 * @param sessionId - the Session that was just created.
 * @param input - effective preset name (optional) and approval policy.
 * @returns what was applied, or undefined when no live Agent was found.
 */
async function applyPermissionPosture(ctx, sessionId, input) {
  const result = await ctx.sessionController.resolveAgent(sessionId)
  if (result?.error !== undefined || result?.agent === undefined) return undefined
  const agent = result.agent
  if (input.permissionPreset !== undefined) {
    ctx.permissionPresets.set(agent.session, input.permissionPreset)
  }
  // A no-op when the policy already matches, so a deployment that configures
  // `never` service-wide sees no spurious notice.
  ctx.approval.setPolicy(agent, input.approvalPolicy)
  return {
    ...(input.permissionPreset === undefined ? {} : { permissionPreset: input.permissionPreset }),
    approvalPolicy: input.approvalPolicy,
  }
}

/**
 * Establish where a newly created Session lives, and report that Workspace.
 *
 * `session.create` attaches a Session to a Workspace only when the caller
 * named one by id. A `cwd` call therefore creates an Ungrouped Session, which
 * is not what a caller naming a project directory means — so this resolves or
 * creates the Workspace for that canonical path and attaches it. Membership
 * requires both an id on the ledger and a Session header whose canonical cwd
 * equals the Workspace path, which is what that establishes.
 * `workspaceRegistry.create` is idempotent per canonical path, so repeated
 * calls never duplicate a Workspace.
 *
 * A Workspace named by id was already attached by `session.create`; this only
 * reads it back, so both spellings report the same location in the response.
 *
 * @param ctx - Host context carrying the Workspace registry.
 * @param input - created Session identity plus the caller's requested location.
 * @returns the owning Workspace, or undefined when the caller named no location.
 */
async function resolveCreatedWorkspace(ctx, input) {
  if (input.workspaceId !== undefined) {
    return ctx.workspaceRegistry.get(input.workspaceId)
  }
  if (input.cwd === undefined) return undefined
  let workspace = await ctx.workspaceRegistry.resolveByPath(input.cwd)
  workspace ??= await ctx.workspaceRegistry.create(input.cwd)
  await workspace.attachSession(input.sessionId)
  return workspace
}

/**
 * Per-location chains guarding Workspace placement.
 *
 * Keyed by the caller's own spelling — a Workspace id or a canonical directory
 * — so two callers naming one location queue behind each other while unrelated
 * locations stay parallel.
 */
const workspaceLocks = new Map()

/**
 * Serialize one keyed operation behind every earlier operation on the same key.
 *
 * The Workspace registry serializes its own domain writes, but a
 * read-modify-write through a `Workspace` handle is not atomic across callers:
 * concurrent `attachSession` calls against one Workspace lose records with
 * `... has no record ... to update`, and concurrent `create` calls for one
 * canonical path can race the same way. A load test of 30 simultaneous
 * `POST /sessions` on one directory failed 14 of them this way, so the gateway
 * holds a per-location lock instead of relying on the registry.
 *
 * Different locations stay fully parallel; only callers naming the same
 * directory or the same Workspace queue behind each other.
 *
 * @param locks - the chain table, owned by the caller.
 * @param key - the location being mutated.
 * @param task - the operation to run exclusively for that location.
 * @returns the task's result.
 */
function withLocationLock(locks, key, task) {
  const previous = locks.get(key) ?? Promise.resolve()
  // Run regardless of how the predecessor settled: one caller's failure must
  // not poison the queue for the next.
  const result = previous.then(task, task)
  const settled = result.then(() => undefined, () => undefined)
  locks.set(key, settled)
  return result.finally(() => {
    if (locks.get(key) === settled) locks.delete(key)
  })
}

/**
 * Register the gateway routes on the injected WebServer.
 * @param ctx - Host context.
 * @param config - raw loader config.
 */
export function apply(ctx, config) {
  const resolved = resolveConfig(config)
  const log = ctx.logger

  /**
   * Sessions an HTTP request is driving right now.
   *
   * Ownership has to be per-turn, not per-Session. A Session-level latch would
   * mean that touching a Session once through the API hijacks every later
   * interaction in it — including the ones raised while a human is typing in
   * the GUI, which would then silently time out with no modal ever shown. So
   * the relay claims an ask only while a caller is actually waiting on that
   * Session's turn.
   */
  const driving = new Set()

  /**
   * Whether an HTTP caller currently owns this Session's turn.
   *
   * Two states count, and they are what a single parked turn alternates
   * between: a request is inside `advanceTurn` awaiting the turn, or the turn
   * parked and the caller holds the `202` that must be answered.
   */
  const isHttpOwned = (sessionId) => driving.has(sessionId) || parkedTurns.has(sessionId)
  /**
   * Interactions waiting for the HTTP caller, keyed by the id handed out.
   *
   * Two seams can block a turn on a human, and both go through here: the
   * approval waterfall (may this one action proceed) and the user-questions
   * waterfall (`ask_user_question`, the option cards). They are separate
   * harness seams with different payloads, but from a bridge's point of view
   * they are the same event — the turn stopped and wants an answer.
   */
  const pendingInteractions = new Map()
  /**
   * Turns parked on an unanswered interaction, keyed by the Session that owns
   * them. Parking is what lets one endpoint serve the whole conversation: the
   * call that started the turn returns the question, and the call that answers
   * it resumes waiting on this promise.
   */
  const parkedTurns = new Map()
  /** Callers waiting to learn that their Session produced an interaction. */
  const interactionWaiters = new Map()
  let interactionSeq = 0

  /** Wake every caller waiting on one Session's next interaction. */
  const announceInteraction = (sessionId) => {
    const waiters = interactionWaiters.get(sessionId)
    if (waiters === undefined) return
    interactionWaiters.delete(sessionId)
    for (const wake of [...waiters]) wake()
  }

  /**
   * Resolve once one Session has a pending interaction, or once its turn
   * promise settles first.
   *
   * The turn is blocked inside the tool call while the harness waits, so
   * neither side can be assumed to win: an interaction that times out unblocks
   * the turn without any caller answering.
   *
   * @param sessionId - the Session being driven.
   * @param turnSettled - promise for the turn's completion.
   * @returns which of the two happened first.
   */
  const raceInteraction = (sessionId, turnSettled) => new Promise((resolve) => {
    let done = false
    let wake
    const settle = (value) => {
      if (done) return
      done = true
      interactionWaiters.get(sessionId)?.delete(wake)
      resolve(value)
    }
    const firstPending = () => [...pendingInteractions.values()].find(entry => entry.sessionId === sessionId)
    const existing = firstPending()
    if (existing !== undefined) return settle({ kind: 'interaction', entry: existing })
    wake = () => {
      const entry = firstPending()
      if (entry !== undefined) settle({ kind: 'interaction', entry })
    }
    if (!interactionWaiters.has(sessionId)) interactionWaiters.set(sessionId, new Set())
    interactionWaiters.get(sessionId).add(wake)
    turnSettled.then(outcome => settle({ kind: 'turn', outcome }))
  })

  /**
   * Offer one approval request to the HTTP caller and wait for its decision.
   *
   * This answerer is the whole point of the relay: the harness asks, no human
   * is watching the UI, so the question is handed to the HTTP caller and the
   * turn stays parked until the same endpoint receives the decision. Every
   * path that is not an explicit grant settles on `rejected`, which is what
   * the tool pipeline fails closed on — a timeout, a cancelled turn, or an
   * unloaded plugin can only ever deny.
   *
   * @param request - the harness's approval request.
   * @param sessionId - the Session that is asking.
   * @returns the closed outcome for the tool pipeline.
   */
  const relayApproval = (request, sessionId) => new Promise((resolve) => {
    interactionSeq += 1
    const approvalId = `approval-${interactionSeq}`
    let timer
    let settled = false
    const entry = {
      kind: 'approval',
      approvalId,
      sessionId,
      toolName: request.toolName,
      requestedAt: Date.now(),
      expiresAt: Date.now() + resolved.approvalTimeoutMs,
      ...(request.callId === undefined ? {} : { callId: request.callId }),
      ...(request.reason === undefined ? {} : { reason: request.reason }),
    }

    const finish = (outcome) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      request.signal?.removeEventListener?.('abort', onAbort)
      pendingInteractions.delete(approvalId)
      resolve(outcome)
    }
    const onAbort = () => finish('rejected')

    entry.decide = (outcome) => {
      const decided = !settled
      finish(outcome)
      return decided
    }
    timer = setTimeout(() => finish('rejected'), resolved.approvalTimeoutMs)
    if (typeof timer.unref === 'function') timer.unref()
    request.signal?.addEventListener?.('abort', onAbort, { once: true })

    pendingInteractions.set(approvalId, entry)
    log?.info?.(
      `session-http: ${approvalId} pending — session ${sessionId} wants "${request.toolName}"`
      + `${request.reason === undefined ? '' : ` (${request.reason})`}`,
    )
    // A caller already waiting on this Session's turn must learn about the
    // question now, so its request can return instead of hanging.
    announceInteraction(sessionId)
  })

  /**
   * Offer one `ask_user_question` request to the HTTP caller.
   *
   * A question is not an approval: the answerer has to produce the structured
   * `{ answers }` the asker validates, and there is no "denied" outcome to fall
   * back on. A timeout therefore rejects, which is what delegating to no
   * answerer would have done — the alternative, synthesising a skip, would
   * report a human decision that never happened.
   *
   * @param request - the harness's user-questions request.
   * @param sessionId - the Session that is asking.
   * @returns the answer the asker is waiting for.
   */
  const relayQuestion = (request, sessionId) => new Promise((resolve, reject) => {
    interactionSeq += 1
    const questionId = `question-${interactionSeq}`
    let timer
    let settled = false
    const entry = {
      kind: 'question',
      questionId,
      sessionId,
      questions: request.questions,
      requestedAt: Date.now(),
      expiresAt: Date.now() + resolved.approvalTimeoutMs,
    }

    const finish = (settle) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      request.signal?.removeEventListener?.('abort', onAbort)
      pendingInteractions.delete(questionId)
      settle()
    }
    const onAbort = () => finish(() => reject(new Error('the question was cancelled')))

    entry.answer = (answers) => {
      const answered = !settled
      finish(() => resolve({ answers }))
      return answered
    }
    timer = setTimeout(
      () => finish(() => reject(new Error(`no answer within ${resolved.approvalTimeoutMs} ms`))),
      resolved.approvalTimeoutMs,
    )
    if (typeof timer.unref === 'function') timer.unref()
    request.signal?.addEventListener?.('abort', onAbort, { once: true })

    pendingInteractions.set(questionId, entry)
    log?.info?.(`session-http: ${questionId} pending — session ${sessionId} asked ${request.questions.length} question(s)`)
    announceInteraction(sessionId)
  })

  if (resolved.relayApprovals) {
    /*
     * Both answerers register with `prepend`.
     *
     * The Web application forwards these same two waterfalls to the browser
     * through an ordinary `ctx.on` listener that claims whenever the dispatch
     * carries an Agent — which is always, for these events. A waterfall runs in
     * registration order, and that forwarder is mounted by a bundle that loads
     * before this plugin, so without `prepend` it would answer first and the
     * HTTP caller would never see the question. Prepending puts the relay in
     * front; an unmanaged Session then falls through with `next()`, which is
     * what still lands on the browser's modal.
     */
    ctx.effect(
      () => ctx.on('approval/request', (request, next) => {
        const sessionId = request?.agent?.session?.id
        if (sessionId === undefined || !isHttpOwned(sessionId)) return next()
        return relayApproval(request, sessionId)
      }, { prepend: true }),
      'session-http: relayed approval answerer',
    )
    ctx.effect(
      () => ctx.on('user-questions/request', (request, next) => {
        const sessionId = request?.agent?.session?.id
        if (sessionId === undefined || !isHttpOwned(sessionId)) return next()
        return relayQuestion(request, sessionId)
      }, { prepend: true }),
      'session-http: relayed user-question answerer',
    )
    // Unloading must not leave a parked turn waiting on a promise nobody can
    // settle, so every pending ask resolves as the plugin goes away.
    ctx.effect(() => () => {
      for (const entry of [...pendingInteractions.values()]) {
        if (entry.kind === 'approval') entry.decide('rejected')
        else entry.answer([])
      }
    }, 'session-http: drain relayed interactions')
  }

  /**
   * Shared preamble: resolve the credential, authenticate, then hand the
   * request to the operation.
   *
   * The credential is resolved per request rather than cached at load: the
   * seam's contract is that consumers re-resolve at each operation, and that
   * per-operation read is exactly what makes a rotated key reach the very
   * next call without a restart.
   *
   * @param req - request owner.
   * @param res - response owner.
   * @param operation - the authenticated handler.
   */
  const guard = async (req, res, operation) => {
    let credential
    try {
      credential = await ctx.credentials.resolve(resolved.secretEnv)
    } catch (error) {
      log?.error?.(`session-http: credential resolution failed: ${String(error)}`)
      return sendError(
        res,
        503,
        'gateway/credential-unavailable',
        `Credential reference "${resolved.secretEnv}" could not be resolved.`,
      )
    }
    if (credential === undefined) {
      return sendError(
        res,
        503,
        'gateway/unconfigured',
        `Credential reference "${resolved.secretEnv}" is not configured. `
        + 'Set that environment variable, or store it in $DSH_HOME/.credentials.yaml.',
      )
    }
    if (!secretMatches(apiKeyOf(req), credential.value)) {
      sendError(res, 401, 'unauthorized', 'Missing or invalid X-Api-Key header.')
      return
    }
    try {
      await operation()
    } catch (error) {
      const code = error?.code
      if (code === 'too-large') return sendError(res, 413, 'request/too-large', error.message)
      if (code === 'bad-json') return sendError(res, 400, 'request/bad-json', error.message)
      log?.error?.(`session-http: ${String(error?.stack ?? error)}`)
      sendError(res, 500, 'internal', error instanceof Error ? error.message : String(error))
    }
  }

  /**
   * Describe one parked turn's blocking interaction.
   *
   * The payload is deliberately self-describing: `reply` names the exact URL
   * and body that resumes the turn, so a caller never needs a second endpoint
   * (or any out-of-band agreement) to answer it. Two harness seams can park a
   * turn, and they keep distinct shapes because their answers differ — an
   * approval is a verdict, a question is structured input.
   */
  const interactionRequiredBody = (sessionId, entry) => {
    const path = `/sessions/${sessionId}/messages`
    if (entry.kind === 'question') {
      return {
        sessionId,
        status: 'question-required',
        questionId: entry.questionId,
        questions: entry.questions,
        expiresAt: entry.expiresAt,
        reply: {
          method: 'POST',
          path,
          body: {
            questionId: entry.questionId,
            answers: entry.questions.map(question => ({
              id: question.id,
              selected: (question.options ?? []).slice(0, 1).map(option => option.label),
            })),
          },
        },
      }
    }
    return {
      sessionId,
      status: 'approval-required',
      approvalId: entry.approvalId,
      toolName: entry.toolName,
      ...(entry.callId === undefined ? {} : { callId: entry.callId }),
      ...(entry.reason === undefined ? {} : { reason: entry.reason }),
      expiresAt: entry.expiresAt,
      reply: {
        method: 'POST',
        path,
        body: { approvalId: entry.approvalId, decision: 'allow' },
      },
    }
  }

  /** Map a settled turn onto an HTTP status and JSON body. */
  const turnBody = (messageId, outcome) => {
    if (outcome.kind === 'timeout') {
      return {
        status: 504,
        body: {
          error: {
            code: 'turn/timeout',
            message: `No turn completed within ${resolved.turnTimeoutMs} ms; the message stays queued.`,
          },
        },
      }
    }
    if (outcome.kind === 'discarded') {
      return {
        status: 409,
        body: { error: { code: 'turn/discarded', message: 'The message was discarded before it ran.' } },
      }
    }
    const described = describeTurnEnd(outcome.reason)
    const turn = { messageId, turn: outcome.turn, completed: described.code === 'completed' }
    if (described.code !== 'completed') {
      return {
        status: 200,
        body: {
          ...turn,
          code: described.code,
          text: outcome.text === '' ? resolved.turnErrorText : outcome.text,
          error: { code: described.code, message: described.message },
        },
      }
    }
    return { status: 200, body: { ...turn, text: outcome.text } }
  }

  /**
   * Drive one started turn to its next stopping point: either the turn
   * finishes, or it parks on an interaction the caller must answer.
   *
   * A parked turn is not lost work — the harness is still blocked inside the
   * tool call, and the promise stashed here is what the answering request
   * resumes waiting on.
   */
  const advanceTurn = async (sessionId, messageId, turnSettled) => {
    driving.add(sessionId)
    try {
      const raced = await raceInteraction(sessionId, turnSettled)
      if (raced.kind === 'interaction') {
        const parked = { turnSettled, messageId }
        parkedTurns.set(sessionId, parked)
        // A parked turn that nobody answers still ends on its own (the relay
        // times out and the tool fails). Releasing the park then is what hands
        // the Session back, so a later GUI turn in it opens its own modal
        // instead of being hijacked by an idle gateway. The identity check
        // keeps this from clearing a newer park.
        void turnSettled.then(() => {
          if (parkedTurns.get(sessionId) === parked) parkedTurns.delete(sessionId)
        })
        return { status: 202, body: interactionRequiredBody(sessionId, raced.entry) }
      }
      return turnBody(messageId, raced.outcome)
    } finally {
      driving.delete(sessionId)
    }
  }

  /**
   * Deliver one human message and drive its turn.
   *
   * Shared by `POST /sessions/{id}/messages` and by `POST /sessions` when the
   * caller supplies a first `text`: for a chat bridge those are one logical
   * operation, and folding them together is also what makes a freshly created
   * Session appear in the GUI, because a Session leaves the hidden `blank`
   * state only once a turn starts.
   */
  const startTurn = async (sessionId, text) => {
    const result = await ctx.sessionController.resolveAgent(sessionId)
    if (result?.error !== undefined || result?.agent === undefined) {
      const message = result?.error?.message ?? `Session "${sessionId}" could not be resolved.`
      return { status: 404, body: { error: { code: 'session/not-found', message } } }
    }
    const message = createHumanMessage(text)
    // Arm the waiter before delivering, so the claim event cannot be missed.
    const pending = waitForTurn(ctx, sessionId, message.id, resolved.turnTimeoutMs)
    result.agent.followup(message)
    return advanceTurn(sessionId, message.id, pending)
  }

  /**
   * Answer one parked turn's interaction and continue driving it.
   *
   * An interaction is only valid for the Session that raised it, so a reply
   * aimed at the wrong Session is refused rather than applied.
   *
   * @param sessionId - the Session named in the URL.
   * @param interactionId - the id from the parked turn's payload.
   * @param reply - the caller's decision or answer, already validated.
   */
  const answerInteraction = async (sessionId, interactionId, reply) => {
    const entry = pendingInteractions.get(interactionId)
    if (entry === undefined || entry.sessionId !== sessionId) {
      return {
        status: 404,
        body: {
          error: {
            code: 'interaction/not-found',
            message: `Interaction "${interactionId}" is not pending for session "${sessionId}".`,
          },
        },
      }
    }
    const parked = parkedTurns.get(sessionId)
    // Settle the ask first: the tool call resumes as soon as it is answered.
    if (entry.kind === 'approval') entry.decide(reply)
    else entry.answer(reply)
    if (parked === undefined) {
      return { status: 200, body: { interactionId, status: 'answered' } }
    }
    return advanceTurn(sessionId, parked.messageId, parked.turnSettled)
  }

  /**
   * GET /interactions — every ask still waiting, of both kinds.
   *
   * `/approvals` answers only the permission half, which leaves a caller with
   * no way to see a pending question at all. This is the whole queue, and it is
   * what makes a stuck turn diagnosable: an empty list while a turn reads
   * `running` means the model is simply still working.
   */
  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/interactions',
    handler: (req, res) => guard(req, res, async () => {
      if (req.method !== 'GET') {
        return sendError(res, 405, 'method-not-allowed', 'Use GET /interactions.')
      }
      return sendJson(res, 200, {
        interactions: [...pendingInteractions.values()].map(entry => ({
          kind: entry.kind,
          id: entry.kind === 'approval' ? entry.approvalId : entry.questionId,
          sessionId: entry.sessionId,
          requestedAt: entry.requestedAt,
          expiresAt: entry.expiresAt,
          ...(entry.kind === 'approval'
            ? {
              toolName: entry.toolName,
              ...(entry.callId === undefined ? {} : { callId: entry.callId }),
              ...(entry.reason === undefined ? {} : { reason: entry.reason }),
            }
            : { questions: entry.questions }),
        })),
      })
    }),
  }), 'session-http: GET /interactions')

  /** GET /workspaces */
  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/workspaces',
    handler: (req, res) => guard(req, res, async () => {
      if (req.method !== 'GET') {
        return sendError(res, 405, 'method-not-allowed', 'Use GET /workspaces.')
      }
      const { rows } = workspaceIndex(ctx.workspaceRegistry)
      sendJson(res, 200, {
        workspaces: rows.map(workspace => ({
          workspaceId: workspace.id,
          path: workspace.path,
          title: workspace.title,
          sessionIds: [...workspace.sessionIds],
        })),
      })
    }),
  }), 'session-http: GET /workspaces')

  /**
   * Every /approvals route.
   *
   * A side view of the approval half of the queue, for callers that would
   * rather poll than use the same-endpoint protocol. User questions are not
   * listed here: they have no yes/no verdict, so they are answered through
   * `POST /sessions/{id}/messages` only.
   */
  ctx.effect(() => ctx.webServer.register({
    kind: 'prefix',
    path: '/approvals',
    handler: (req, res) => guard(req, res, async () => {
      const pathname = new URL(req.url ?? '/', 'http://gateway.invalid').pathname
      const approvals = () => [...pendingInteractions.values()].filter(entry => entry.kind === 'approval')

      // GET /approvals — every ask still waiting for a decision.
      if (pathname === '/approvals' && req.method === 'GET') {
        return sendJson(res, 200, {
          approvals: approvals().map(entry => ({
            approvalId: entry.approvalId,
            sessionId: entry.sessionId,
            toolName: entry.toolName,
            ...(entry.callId === undefined ? {} : { callId: entry.callId }),
            ...(entry.reason === undefined ? {} : { reason: entry.reason }),
            requestedAt: entry.requestedAt,
            expiresAt: entry.expiresAt,
          })),
        })
      }

      // POST /approvals/{id} — decide one pending ask.
      const decision = /^\/approvals\/([^/]+)$/.exec(pathname)
      if (decision !== null && req.method === 'POST') {
        const approvalId = decodeSegment(decision[1])
        if (!declaresJson(req)) {
          return sendError(res, 415, 'unsupported-media-type', 'Send Content-Type: application/json.')
        }
        const body = await readJsonBody(req, resolved.maxBodyBytes)
        const outcome = RELAY_DECISIONS.get(body.outcome)
        if (outcome === undefined) {
          return sendError(
            res,
            400,
            'request/bad-request',
            'outcome must be "allow" or "deny".',
          )
        }
        const entry = approvals().find(candidate => candidate.approvalId === approvalId)
        if (entry === undefined) {
          return sendError(
            res,
            404,
            'approval/not-found',
            `Approval "${approvalId}" is not pending; it was decided, timed out, or never existed.`,
          )
        }
        entry.decide(outcome)
        return sendJson(res, 200, { approvalId, sessionId: entry.sessionId, outcome })
      }

      sendError(res, 404, 'not-found', `No session-http route matches ${req.method} ${pathname}.`)
    }),
  }), 'session-http: /approvals routes')

  /**
   * Every /sessions route, matched through one prefix registration.
   *
   * The WebServer offers only `exact` and `prefix`, and a prefix route already
   * covers its own bare path — so one `/sessions` registration serves the list,
   * the create, and the per-Session routes without an exact/prefix collision.
   */
  ctx.effect(() => ctx.webServer.register({
    kind: 'prefix',
    path: '/sessions',
    handler: (req, res) => guard(req, res, async () => {
      const url = new URL(req.url ?? '/', 'http://gateway.invalid')
      const pathname = url.pathname
      const detail = /^\/sessions\/([^/]+)$/.exec(pathname)
      const messages = /^\/sessions\/([^/]+)\/messages$/.exec(pathname)
      const bare = pathname === '/sessions'

      // GET /sessions — list visible Sessions with their Workspace.
      //
      // Visibility mirrors the GUI's sidebar, which hides archived Sessions
      // and blank ones (created but never prompted). A caller comparing this
      // list against the sidebar would otherwise see rows the UI never shows,
      // so hiding is the default and both opt-ins are explicit.
      if (bare && req.method === 'GET') {
        const { bySession, archived } = workspaceIndex(ctx.workspaceRegistry)
        const includeArchived = url.searchParams.get('includeArchived') === 'true'
        const includeBlank = url.searchParams.get('includeBlank') === 'true'
        const { items } = await ctx.sessionController.list({}, NO_ABORT)
        const rows = items.map(item => {
          const workspace = bySession.get(item.sessionId)
          const title = titleOfSummary(item)
          return {
            sessionId: item.sessionId,
            title,
            displayTitle: displayTitleOf(title, item.cwd, item.sessionId),
            cwd: item.cwd ?? null,
            updatedAt: item.updatedAt,
            running: item.running === true,
            blank: item.blank === true,
            archived: archived.has(item.sessionId),
            workspaceId: workspace?.id ?? null,
            workspacePath: workspace?.path ?? null,
          }
        })
        return sendJson(res, 200, {
          sessions: rows.filter(row => (includeArchived || !row.archived) && (includeBlank || !row.blank)),
        })
      }

      // POST /sessions — create or adopt one Session.
      if (bare && req.method === 'POST') {
        if (!declaresJson(req)) {
          return sendError(res, 415, 'unsupported-media-type', 'Send Content-Type: application/json.')
        }
        const body = await readJsonBody(req, resolved.maxBodyBytes)
        if (body.workspaceId !== undefined && body.cwd !== undefined) {
          return sendError(res, 400, 'request/bad-request', 'Provide workspaceId or cwd, not both.')
        }
        if (body.workspaceId !== undefined && typeof body.workspaceId !== 'string') {
          return sendError(res, 400, 'request/bad-request', 'workspaceId must be a string.')
        }
        if (body.cwd !== undefined && typeof body.cwd !== 'string') {
          return sendError(res, 400, 'request/bad-request', 'cwd must be a string.')
        }
        if (body.sessionId !== undefined && typeof body.sessionId !== 'string') {
          return sendError(res, 400, 'request/bad-request', 'sessionId must be a string.')
        }
        if (body.text !== undefined && (typeof body.text !== 'string' || body.text.trim() === '')) {
          return sendError(res, 400, 'request/bad-request', 'text must be a non-empty string when provided.')
        }
        const permissionPreset = body.permissionPreset ?? resolved.permissionPreset
        if (permissionPreset !== undefined) {
          if (typeof permissionPreset !== 'string' || permissionPreset.trim() === '') {
            return sendError(res, 400, 'request/bad-request', 'permissionPreset must be a non-empty string.')
          }
          try {
            ctx.permissionPresets.resolve(permissionPreset)
          } catch (error) {
            return sendError(
              res,
              400,
              'request/unknown-permission-preset',
              error instanceof Error ? error.message : String(error),
            )
          }
        }
        const approvalPolicy = body.approvalPolicy ?? resolved.approvalPolicy
        if (!APPROVAL_POLICIES.includes(approvalPolicy)) {
          return sendError(
            res,
            400,
            'request/bad-request',
            `approvalPolicy must be one of ${APPROVAL_POLICIES.join(', ')}.`,
          )
        }
        const request = {
          ...(body.sessionId === undefined ? {} : { sessionId: body.sessionId }),
          ...(body.workspaceId === undefined ? {} : { workspaceId: body.workspaceId }),
          ...(body.cwd === undefined ? {} : { cwd: body.cwd }),
          ...(body.agentPreset !== undefined
            ? { agentPreset: body.agentPreset }
            : resolved.defaultAgentPreset === undefined
              ? {}
              : { agentPreset: resolved.defaultAgentPreset }),
        }
        try {
          const created = await ctx.sessionController.create(request)
          // Both spellings must report the same location: a Workspace named by
          // id was attached by `session.create`, while a `cwd` call needs the
          // attach this performs, or the Session would stay Ungrouped.
          //
          // The attach runs under a per-location lock because concurrent
          // read-modify-write through one Workspace handle loses records.
          const locationKey = body.workspaceId ?? body.cwd
          const attached = locationKey === undefined
            ? undefined
            : await withLocationLock(workspaceLocks, locationKey, () => resolveCreatedWorkspace(ctx, {
              sessionId: created.sessionId,
              workspaceId: body.workspaceId,
              cwd: body.cwd,
            })).catch((error) => {
              // Grouping is presentation, not the Session's existence: the log
              // is already durable and addressable. Failing the whole request
              // would strand a Session the caller could never name again, so
              // report it as created but ungrouped.
              log?.warn?.(
                `session-http: created ${created.sessionId} but could not place it in a Workspace: ${String(error)}`,
              )
              return undefined
            })
          const location = attached === undefined
            ? {}
            : { workspaceId: attached.id, workspacePath: attached.path }
          // Permissions first: a turn must never start under a policy that
          // would open a modal the caller cannot answer.
          const posture = await applyPermissionPosture(ctx, created.sessionId, {
            permissionPreset,
            approvalPolicy,
          })
          const applied = posture === undefined ? {} : posture
          if (body.text === undefined) {
            return sendJson(res, 200, { ...created, ...location, ...applied })
          }
          // A first message was supplied, so this call is the whole
          // create-and-speak operation: the response carries the turn's answer
          // and the Session stops being hidden. It may instead park on an
          // approval, which the same URL then answers.
          const outcome = await startTurn(created.sessionId, body.text)
          return sendJson(res, outcome.status, { ...created, ...location, ...applied, ...outcome.body })
        } catch (error) {
          const code = error?.code
          // A Session whose create succeeded but whose Workspace attach failed
          // still exists and is addressable. Losing its id to a 400 would
          // strand it, and the error already carries the identity, so report
          // the creation and let the caller carry on ungrouped.
          const stranded = error?.details?.sessionId
          if (code === 'session/workspace-attach-failed' && typeof stranded === 'string') {
            log?.warn?.(
              `session-http: created ${stranded} but could not place it in a Workspace: ${String(error)}`,
            )
            return sendJson(res, 200, { sessionId: stranded, workspaceAttach: 'failed' })
          }
          const failure = code === 'workspace/not-found' ? 'workspace/not-found' : 'session/create-failed'
          const status = failure === 'workspace/not-found' ? 404 : 400
          return sendError(res, status, failure, error instanceof Error ? error.message : String(error))
        }
      }

      // GET /sessions/{id} — one Session's detail, without activating an Agent.
      // Detail is addressable even for a hidden Session: knowing the id is
      // enough, and that is what makes an archived Session inspectable.
      if (detail !== null && req.method === 'GET') {
        const sessionId = decodeSegment(detail[1])
        const { bySession, archived } = workspaceIndex(ctx.workspaceRegistry)
        const workspace = bySession.get(sessionId)
        try {
          const inspection = await ctx.sessionController.inspect(sessionId, NO_ABORT)
          // The title is a projection carried by the list snapshot, not by the
          // header `inspect` returns, so read it from there and tolerate a
          // failed list read rather than failing the whole detail request.
          let title = null
          try {
            const { items } = await ctx.sessionController.list({}, NO_ABORT)
            title = titleOfSummary(items.find(item => item.sessionId === sessionId))
          } catch (error) {
            log?.warn?.(`session-http: title lookup failed for "${sessionId}": ${String(error)}`)
          }
          return sendJson(res, 200, {
            sessionId,
            title,
            displayTitle: displayTitleOf(title, inspection.meta.cwd, sessionId),
            cwd: inspection.meta.cwd ?? null,
            workspaceId: workspace?.id ?? null,
            workspacePath: workspace?.path ?? null,
            archived: archived.has(sessionId),
            attached: ctx.sessions.get(sessionId) !== undefined,
            eventCount: inspection.events.length,
          })
        } catch (error) {
          return sendError(res, 404, 'session/not-found', error instanceof Error ? error.message : String(error))
        }
      }

      // POST /sessions/{id}/messages — one endpoint, three verbs.
      //
      //   { "text": "…" }                              start a turn
      //   { "approvalId": "…", "decision": "allow" }   answer a permission ask
      //   { "questionId": "…", "answers": [ … ] }      answer an option card
      //
      // A turn that stops for a human parks instead of hanging: the response is
      // `202` describing what is being asked, and the caller answers it by
      // posting back to this same URL. That keeps a bridge to a single
      // request/response shape with no polling and no second channel.
      if (messages !== null && req.method === 'POST') {
        const sessionId = decodeSegment(messages[1])
        if (!declaresJson(req)) {
          return sendError(res, 415, 'unsupported-media-type', 'Send Content-Type: application/json.')
        }
        const body = await readJsonBody(req, resolved.maxBodyBytes)

        if (body.approvalId !== undefined || body.decision !== undefined) {
          if (typeof body.approvalId !== 'string' || body.approvalId.trim() === '') {
            return sendError(res, 400, 'request/bad-request', 'approvalId must be a non-empty string.')
          }
          const outcome = RELAY_DECISIONS.get(body.decision ?? body.outcome)
          if (outcome === undefined) {
            return sendError(res, 400, 'request/bad-request', 'decision must be "allow" or "deny".')
          }
          const answered = await answerInteraction(sessionId, body.approvalId, outcome)
          return sendJson(res, answered.status, { sessionId, ...answered.body })
        }

        if (body.questionId !== undefined || body.answers !== undefined) {
          if (typeof body.questionId !== 'string' || body.questionId.trim() === '') {
            return sendError(res, 400, 'request/bad-request', 'questionId must be a non-empty string.')
          }
          const pending = pendingInteractions.get(body.questionId)
          if (pending === undefined || pending.kind !== 'question' || pending.sessionId !== sessionId) {
            return sendError(
              res,
              404,
              'interaction/not-found',
              `Question "${body.questionId}" is not pending for session "${sessionId}".`,
            )
          }
          const validated = validateQuestionAnswers(body.answers, pending.questions)
          if (validated.error !== undefined) {
            return sendError(res, 400, 'request/bad-request', validated.error)
          }
          const answered = await answerInteraction(sessionId, body.questionId, validated.answers)
          return sendJson(res, answered.status, { sessionId, ...answered.body })
        }

        if (typeof body.text !== 'string' || body.text.trim() === '') {
          return sendError(res, 400, 'request/bad-request', 'text must be a non-empty string.')
        }
        // A turn already parked on an interaction: hand the same ask back
        // rather than starting a second turn behind it.
        const parkedEntry = [...pendingInteractions.values()].find(entry => entry.sessionId === sessionId)
        if (parkedTurns.has(sessionId) && parkedEntry !== undefined) {
          return sendJson(res, 202, interactionRequiredBody(sessionId, parkedEntry))
        }
        const outcome = await startTurn(sessionId, body.text)
        return sendJson(res, outcome.status, { sessionId, ...outcome.body })
      }

      sendError(res, 404, 'not-found', `No session-http route matches ${req.method} ${pathname}.`)
    }),
  }), 'session-http: /sessions routes')

  log?.info?.(
    `session-http: gateway registered on GET /workspaces and /sessions routes; `
    + `resolving credential reference "${resolved.secretEnv}" per request`,
  )
}

/*
 * No `export default`: the Cordis Loader normalizes a module through
 * `unwrapExports`, which prefers `.default`. A default export would replace
 * the module namespace and drop the sibling `name`/`inject` exports, leaving
 * `apply` to run in a fiber that grants no services — see
 * docs/postmortem/0001-acp-default-export-drops-inject.md.
 */
