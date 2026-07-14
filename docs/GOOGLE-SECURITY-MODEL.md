# Google agentic security model

## Core invariant

Approval is an authorization envelope, not an IAM grant handed to the model:

`agent identity + human purpose + capability + resource + constraints + expiry`

Every action must satisfy the full envelope. The gateway acquires any real credential only after
that decision and never returns it to the agent. This separates the model's untrusted reasoning
plane from the credential and policy control plane.

## Control flow

1. An agent authenticates and declares a natural-language purpose plus machine-enforceable scope.
2. The gateway computes an explainable risk score from capability impact, resource breadth, data
   sensitivity, egress, guardrail posture, and action volume.
3. A human approves or denies the complete purpose envelope.
4. The approved agent exchanges its identity for one opaque, expiring handle.
5. Every action is checked against the immutable envelope and screened before execution.
6. The gateway injects Application Default Credentials for a constructed, allowlisted Google API
   endpoint. The agent never sees the token.
7. Declaration, approval, denial, execution, failure, and guardrail decisions enter a hash chain.

## Alignment with Google's stack

### SAIF

The design maps to SAIF's practical themes: strong access control around model-facing systems,
automated defenses against prompt attacks, consistent controls across the agent lifecycle, and
monitoring that treats model inputs and actions as security-relevant events. The deterministic
policy engine is authoritative; an LLM may enrich risk explanations later but must not grant
access.

### Agent Identity

The local API key is only a development stand-in. On Gemini Enterprise Agent Platform Runtime,
replace it with verification of the agent's SPIFFE-based identity and certificate-bound
credentials. Preserve both identities when delegation is used:

- actor: the cryptographically attested agent principal
- authority: the end user on whose behalf it acts
- approver: the human or policy authority that approved the purpose

Production authorization should combine this purpose envelope with IAM allow and deny policies,
Principal Access Boundaries, VPC Service Controls, mTLS, and DPoP. The purpose gateway narrows what
the agent may ask for; Google Cloud policy remains the non-bypassable outer boundary.

### Model Armor

`MODEL_ARMOR_ENDPOINT` enables inline prompt screening with an organization-managed template.
Production use should screen:

- user input before planning
- retrieved context and tool descriptions before model ingestion
- tool arguments before execution
- tool results before they return to the model
- final responses before user or agent delivery

The MVP screens tool input and has conservative local secret/injection checks. A production
deployment should fail closed when the required Model Armor policy is unavailable, classify the
result rather than inspect response strings, and log only hashes and non-sensitive findings.

### Agent2Agent

The Agent Card advertises purpose declaration as a skill. Production A2A support should add:

- signed Agent Cards and trusted issuer policy
- mTLS/DPoP-bound agent authentication
- propagation of task, trace, actor, authority, and approval IDs
- receiver-side re-authorization (never transitively trust the caller's approval)
- delegation-depth, recipient, data-classification, and egress constraints
- cancellation and revocation propagation across the task graph

An A2A call is a new trust-boundary crossing. `google.a2a.send` therefore carries an explicit risk
premium and requires external communication approval.

### Gemini Enterprise / Agentspace

Search and connector access should use user-delegated authority where the data belongs to a user,
while retaining the agent principal for attribution. Purpose approval must not broaden connector
ACLs. Search results should be filtered by the user's existing access and screened before being
placed in model context.

The code retains `google.agentspace.search` as a capability name so policy remains stable while
Google product naming evolves.

### Vertex AI Agent Builder and Agent Engine

Deploy the gateway as a separate control-plane service reachable from Agent Engine, ideally behind
Agent Gateway/IAP. Give each runtime its own Agent Identity. Compile frequently used purpose
templates into narrowly scoped IAM and Principal Access Boundary policies, while retaining
per-task TTL, budgets, and resource restrictions in the gateway.

The only live executor in this MVP is `google.vertex.generate`. It constructs the Vertex endpoint
from an approved publisher-model resource and uses server-side Application Default Credentials;
the agent cannot supply an arbitrary URL.

### Governance and audit

The local hash chain makes deletion or reordering detectable only while a trusted checkpoint
exists elsewhere. Production should export structured events to Cloud Logging with:

- agent principal, delegated user, approver, task, handle, trace, and request IDs
- policy version and Model Armor template/version
- purpose, capabilities, resource selectors, TTL, budgets, and risk factors
- decision reason and input/output hashes, not raw secrets or sensitive prompts
- upstream Google request ID and Cloud Audit Log correlation fields

Anchor periodic chain roots in an immutable store, route high-risk findings to Security Command
Center, define retention and legal-hold policy, and test replay against Cloud Audit Logs.

## Threat boundaries

- Treat model output, retrieved content, MCP/A2A metadata, and tool arguments as hostile input.
- Run agents separately from the gateway; co-location lets an agent read the database or process
  credentials and bypass policy.
- Never let an agent choose an upstream URL, OAuth scope, service account, or credential source.
- Hashing handles protects database disclosure only when handles have enough entropy; it does not
  prevent theft from the agent runtime.
- Short TTL limits duration, while capability/resource/action budgets limit blast radius.
- Revocation, concurrency-safe budget consumption, replay protection, rate limiting, and external
  audit anchoring are required before production.

## Recommended production sequence

1. Replace development tokens with workforce identity for reviewers and Google Agent Identity for
   runtimes.
2. Make Model Armor mandatory and fail closed for protected capabilities.
3. Move SQLite to a transactional managed store; atomically authorize and consume budgets.
4. Add handle proof-of-possession binding, revocation, nonce replay protection, and rate limits.
5. Export and anchor audit events in Cloud Logging/immutable storage.
6. Add signed A2A task exchange and receiver-side delegation policy.
7. Add policy-as-code, approval templates, dual control for critical risk, and break-glass review.
8. Validate the complete path with red-team prompt injection, confused-deputy, data exfiltration,
   stale approval, cross-agent replay, and audit-tampering tests.
