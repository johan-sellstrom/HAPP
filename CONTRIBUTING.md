# Contributing

Thanks for your interest in contributing.

## What to contribute

- Specification improvements (clarity, security, privacy, interoperability)
- JSON Schemas and test vectors
- Conformance requirements and harness improvements
- Reference implementations (Presence Provider, Relying Party verifier, adapters)

## Workflow

1. Open an issue describing the change and motivation.
2. Submit a PR that includes:
   - the spec/schema/code change
   - updates to conformance requirements (if the change is normative)
   - tests or test vectors where applicable
3. Keep changes focused and easy to review.

## Spec changes

- Prefer small, reviewable diffs.
- For any new MUST/SHOULD requirement, add:
  - a requirement ID in the conformance document, and
  - at least one positive and one negative test.

## Security and privacy

- Treat the threat model as part of the API surface.
- Avoid adding protocol fields that would require biometrics or sensitive PII to be embedded in credentials.

## License

By contributing, you agree that your contributions are licensed under the repository license.
