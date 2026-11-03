# Auditor/tester phase checklist

Use this phase when a planner has proposed findings and the user wants independent validation, focused RED tests, and a builder-ready handoff without production implementation.

## Procedure

1. Treat planner findings as hypotheses. Re-read the relevant source, callers, configuration, and existing tests.
2. Record exact evidence: repository, commit, file, line range, and observable impact.
3. Choose the smallest testable contract for each finding. Prefer behavior/integration tests; use source-contract tests only where infrastructure or credentials make a behavioral test impractical.
4. Add one focused RED test per behavior. For security boundaries, test both the permitted credential path and the forbidden/admin path. For model routing, test strict rejection of an unavailable explicitly selected model; do not encode silent fallback as acceptable. For streaming, cover both before-headers and after-headers error behavior.
5. Run each new test independently. Confirm it fails for the intended assertion, not because of a typo, import error, fixture defect, or setup problem.
6. Run the relevant existing suite. Distinguish already-passing coverage from newly validated RED contracts, and report real counts and unusually slow tests.
7. Handoff must include: validated findings, evidence, test files/names, failure semantics, builder acceptance criteria, unresolved environment/deployment assumptions, and an explicit statement that no production implementation was made.

## Common auth/proxy checks

- An admin key used to read a scoped catalog must not be reused as the chat-user credential.
- A gateway identity adapter must define algorithm, signature secret, issuer, audience, expiry, subject, and header forwarding semantics.
- Direct chat and alternate/LangChain adapters must share the same user-auth contract.
- Explicit model selection must fail closed when unavailable; never silently replace it with another model/provider.
- Upstream error bodies, credentials, and raw exception messages must not reach clients or logs.
- SSE paths need sanitized handling both before response headers are committed and after an SSE stream has started.

## Handoff quality bar

Do not call a source-string assertion a behavioral proof. Label source contracts as such, explain why they are necessary, and pair them with runtime tests when the boundary can be exercised. Do not claim a JWT is ready merely because a verifier exists: confirm the production token's signing secret, algorithm, issuer, audience, and forwarding path.
