# AGENTS.md — MSST-Net Relay

## 1. Project Role

This repository contains the MSST-Net Relay service.

The Relay is a data-plane forwarding component. Its primary responsibility is to forward traffic between participating clients when direct communication is unavailable or when the protocol explicitly selects relay forwarding.

Before making changes, inspect the repository to establish its actual packet format, transport protocols, session model, authentication mechanisms, resource limits, and deployment architecture.

Do not assume that undocumented security or protocol features already exist.

## 2. Architectural Boundaries

- Keep packet forwarding separate from Coordinator control-plane responsibilities.
- Do not introduce node-directory management, identity-provider functionality, or client-side routing policy into Relay without an explicit architectural decision.
- Do not assume that receiving a packet from a known address proves the sender's identity or authorization.
- Do not treat successful relay registration as unrestricted authorization to forward arbitrary traffic.
- Forward only traffic permitted by the actual protocol and the established session or authorization model.
- Preserve the intended separation between direct peer-to-peer traffic and relay-assisted traffic.
- Do not make ordinary peer-to-peer communication depend on Relay availability unless the protocol explicitly requires it.
- Do not introduce packet inspection or payload modification that changes end-to-end protocol semantics without an explicit requirement.

These are intended architectural boundaries. Verify the current implementation and existing trust model before making changes.

## 3. Required Workflow

Before implementing a non-trivial change:

1. Inspect the service entry points, packet-processing path, session management, configuration, and tests.
2. Trace a packet from ingress through validation and forwarding to egress.
3. Identify how the sender, destination, session, and forwarding permission are established.
4. Determine which component owns each piece of state and how it is invalidated.
5. Identify resource-exhaustion, spoofing, concurrency, and cleanup risks relevant to the change.
6. Present a concise implementation plan and validation strategy before broad modifications.

Prefer small, incremental changes. Avoid unrelated refactoring and unnecessary new dependencies.

If the protocol or trust model is unclear, document the uncertainty rather than inventing security assumptions.

## 4. Packet Processing and Validation

- Validate packet framing and required fields before using them.
- Apply explicit bounds to packet sizes, metadata lengths, and other attacker-controlled values.
- Reject malformed or unsupported packets safely.
- Validate destination and session information against the actual forwarding rules.
- Prevent packets from being forwarded across unrelated sessions or tenants through accidental state reuse.
- Do not trust client-supplied routing metadata or identity claims without the protocol-defined validation.
- Avoid unnecessary packet copies and allocations on the hot path, but never sacrifice correctness or memory safety for speculative performance gains.
- Keep parsing, authorization decisions, and forwarding side effects sufficiently separated to support testing.

Do not assume that the Relay is permitted to decrypt application payloads. Determine the actual protocol and encryption boundary first.

## 5. Resource Limits and Abuse Resistance

- Apply bounded limits to concurrent sessions, queued data, per-session state, and other resources where applicable.
- Prevent unbounded buffering when receivers are slow or unavailable.
- Handle excessive traffic without allowing one client or session to consume all available resources.
- Use appropriate timeouts and cleanup rules for inactive, expired, or disconnected sessions.
- Ensure that malformed traffic cannot create unlimited retained state.
- Avoid uncontrolled task creation, unbounded retry loops, and unbounded channel growth.
- Consider rate limiting and fair resource allocation where they fit the existing architecture.
- Do not introduce limits that silently break legitimate protocol behavior; document and test the selected values.

Resource limits should be explicit, configurable where appropriate, and validated against realistic traffic patterns.

## 6. Concurrency and Session Lifecycle

- Establish clear ownership for session state and forwarding resources.
- Ensure that session creation, forwarding, expiration, and deletion remain correct under concurrent operations.
- Handle duplicate registration, disconnects, stale references, and repeated cleanup safely.
- Prevent packets associated with an expired or replaced session from being delivered through stale state.
- Avoid holding shared locks during unnecessarily long I/O operations.
- Do not introduce asynchronous tasks without defining their cancellation and cleanup behavior.
- Distinguish temporary transport errors from invalid session state and permanent failures.

Test lifecycle transitions and race-sensitive behavior where feasible, rather than testing only successful packet forwarding.

## 7. Transport and Failure Handling

- Inspect existing transport and socket configuration before changing it.
- Use bounded queues, timeouts, and retry policies appropriate to the transport.
- Handle unreachable destinations, socket errors, and client disconnects without leaking resources.
- Avoid retry behavior that amplifies traffic or causes persistent resource exhaustion.
- Do not silently discard errors that leave session state inconsistent.
- Preserve the distinction between a packet being accepted, queued, forwarded, and successfully delivered; do not report stronger guarantees than the implementation provides.
- Do not change transport semantics or packet framing without evaluating client and Coordinator compatibility.

Do not assume that UDP provides delivery guarantees, ordering, congestion control, or authentication.

## 8. Security and Cryptographic Boundaries

- Do not invent a custom encryption, authentication, or key-exchange protocol.
- Do not disable existing authentication or integrity checks to simplify forwarding.
- Do not assume that encryption alone authorizes forwarding.
- Do not log private keys, tokens, session secrets, or sensitive packet contents.
- Ensure that administrative and diagnostic interfaces are not unintentionally exposed to untrusted clients.
- If the Relay terminates an authenticated or encrypted protocol, verify exactly what that implies for payload confidentiality, integrity, and authorization.
- If the Relay forwards opaque end-to-end encrypted packets, preserve their bytes and protocol semantics unless an explicit protocol change is approved.

When a security property cannot be established from the implementation, report it as unverified rather than claiming the service provides it.

## 9. Performance and Observability

- Measure before optimizing.
- Prioritize bounded memory use, predictable latency, and stable behavior under concurrent traffic.
- Avoid expensive parsing, logging, or allocations in the forwarding hot path unless justified.
- Provide useful operational metrics and logs for session counts, forwarding failures, resource limits, and transport errors where supported.
- Avoid high-cardinality metrics and per-packet logging that can overwhelm the service.
- Never include secrets or sensitive payloads in diagnostic output.

Performance changes must preserve forwarding correctness, isolation, and resource limits.

## 10. Testing and Validation

For each change:

- Add or update tests for packet parsing, forwarding decisions, and relevant failure cases.
- Test malformed packets, invalid destinations, expired sessions, and unauthorized forwarding where applicable.
- Test resource limits and cleanup behavior.
- Test concurrent session lifecycle operations when affected.
- Test behavior when the destination is unreachable or the transport fails.
- Run the existing formatter, linter, type checks, and relevant test suite where available.
- Use integration or load tests when the change materially affects transport behavior, concurrency, or throughput.

Do not claim that a test passed unless it was actually executed and its result was observed. Do not remove or weaken tests merely to make a change pass.

## 11. Cross-Repository Compatibility

- Treat packet formats, session identifiers, registration semantics, and forwarding behavior as compatibility-sensitive interfaces.
- Inspect the actual contracts with Coordinator and clients before changing them.
- Do not assume that all components can be upgraded simultaneously.
- Document required changes to other repositories and any deployment-order constraints.
- Avoid introducing hidden dependencies on Coordinator availability for traffic that should already be forwardable.

## 12. Scope Control

- Do not perform a repository-wide rewrite unless explicitly requested.
- Do not replace the transport, concurrency model, or protocol merely to simplify implementation.
- Do not add unrelated features during bug fixes.
- Do not weaken validation, authentication, or resource limits as an incidental consequence of refactoring.
- Report out-of-scope security or reliability defects with evidence and impact; do not silently expand the task.

## 13. Completion Report

At the end of a task, report:

1. What changed and why.
2. Which packet paths, session states, and interfaces were affected.
3. Security, resource-consumption, and compatibility implications.
4. Tests executed and their actual results.
5. Known limitations, unverified assumptions, and follow-up work.

Base conclusions on source code, test results, and observed behavior.