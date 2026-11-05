# Contributing

Follow the [ANS contribution guide](https://github.com/agentnameservice/.github/blob/main/CONTRIBUTING.md)
and [governance](https://github.com/agentnameservice/governance/blob/main/GOVERNANCE.md).
They define DCO sign-off, pull request review, issue references, and disclosure
of AI assistance.

The [Code of Conduct](CODE_OF_CONDUCT.md) applies to all participation.
Report vulnerabilities privately using [SECURITY.md](SECURITY.md).
The repository's [Maintainers](MAINTAINERS.md) handle reviews and releases.

## Licensing new contributions

This policy applies to new original contributions submitted after its adoption.
By submitting such a contribution for inclusion in ANS, you agree to license it
under the [Apache License, Version 2.0](LICENSE), including its copyright and
patent grants. Only submit material that you have the right to license on those
terms, and sign off each commit under the Developer Certificate of Origin below.

Pre-existing contributions retain the licenses under which they were submitted.
In particular, earlier MIT-licensed contributions remain under
[LICENSES/MIT.txt](LICENSES/MIT.txt); this policy does not claim an Apache patent grant from
those contributors for their earlier work. Preserve existing copyright and
third-party license notices when modifying or incorporating material.

## Development

See the [test and lint instructions](README.md#testing) in the README.

## Commit Messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/) to
automate versioning and changelog generation. Commit messages must follow this format:

```text
<type>[optional scope]: <description>
```

Common types:

- `feat:` — A new feature (minor version bump)
- `fix:` — A bug fix (patch version bump)
- `docs:` — Documentation changes
- `chore:` — Maintenance tasks
- `refactor:` — Code refactoring
- `test:` — Test additions or changes
- `ci:` — CI/CD changes
- `perf:` — Performance improvements

Breaking changes: Append `!` after the type (e.g., `feat!: redesign API`) to signal
a breaking change. For a Go module, a major version bump (e.g., v1 to v2) requires
updating the module path to include `/v2`. Discuss with maintainers before introducing
breaking changes.

Commits that do not follow this format are ignored by the release automation and will
not appear in the changelog or trigger a version bump.
