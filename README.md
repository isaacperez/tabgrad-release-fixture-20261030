# Synthetic release-service fixture

This repository is a finite GitHub service qualification, not a Tabgrad
release, npm package, application or deployment. The data, tag, draft and
optional public release are synthetic. No npm identity, job OIDC or producer-signing
permission is provided. Publishing the synthetic immutable release automatically
generates its public GitHub release attestation; that effect needs approval too. Do not install or depend on its release.

The reviewed `fixture.mjs` uses unchanged release primitives from the exact
public Tabgrad source identified by its `SOURCE` constant. It measures actual
manual queue/approval, HTTPS control-record writes/readback, identified artifact
handoffs, read-only draft/asset access and conditional release immutability.
The maintained `visibility/state` path and direct reads are reported separately;
a failure stops completion without expanding the reader's authority.

`FIXTURE_ENABLED` is absent/false by default. Activation, separately admitted
configuration and the two exact dispatches require operational authorization.
Only inspected synthetic data and generated safe observations belong in this
repository or its artifacts. Keep credentials and account/deployment dossiers
outside them. Fixture success does not qualify production identities/settings,
npm authentication, producer signatures, tensor behavior or useful delivery.

Local checks: `node --test fixture.test.mjs`.
The private operational plan owns the allowed runs, cost, custody and recovery;
this README grants no service access or publication authority.
