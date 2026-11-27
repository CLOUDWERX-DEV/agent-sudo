## What changed

<!-- A sentence or two. Why, not just what. -->

## How I tested it

## Checklist

- [ ] `cargo test` passes
- [ ] `cargo clippy --all-targets -- -D warnings` is quiet
- [ ] I added cases: some that must be blocked (including disguised) and some harmless neighbours that must still be allowed
- [ ] The README, `docs/` and the changelog are updated if behavior changed
- [ ] It doesn't add a way for the caller to switch a guardrail off
