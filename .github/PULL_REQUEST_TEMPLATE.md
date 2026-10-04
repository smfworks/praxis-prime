## Summary

<!-- What changed, and why. -->

## Sources
<!-- Required. List anything reused or adapted from someone else: code, text,
     docs, data, design, prompts, models, or changes ported from a fork.
     One per line: name (@handle), link, license, what was used.
     Every source here must also be in CREDITS.md.
     If nothing was reused, write just: none -->

## Blueprint

<!-- ARCHITECTURE sections this touches, if any. Link the heading. -->

## Test plan

- [ ] `ruff check .`
- [ ] `pytest`
- [ ] `praxis-prime --version` and `pprime --version`
- [ ] `praxis-prime doctor`
- [ ] `praxis-prime config` leaves every compliance dial off

## Safety and attribution

- [ ] Compliance dials still default to off
- [ ] No secrets, tokens, or private data
- [ ] No private Praxis pack code copied
- [ ] Any copied upstream file is listed in THIRD_PARTY.md with its license, commit, and notices
