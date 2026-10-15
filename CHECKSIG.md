# CheckSig fork

This is the CheckSig fork of [bitcoin-core/HWI](https://github.com/bitcoin-core/HWI).
Upstream's `README.md` is unchanged.

## Branches

- The default branch is `checksig`.
- `upstream` follows bitcoin-core/HWI. Nothing of ours is committed to it.
- `dev`, `prod01` and `rebased` are long-lived and are not landing targets.

## Landing a change

- A pull request targets `checksig` and lands by squash only.
- Every commit is signed.
- No merge commit is created on `checksig`, and no merge of upstream history into it is accepted.

## Taking an upstream update

1. Branch from the new upstream tag, for example `checksig-<tag>`.
2. Reapply our patches on it (cherry-pick or rebase), signed.
3. Run the fork's tests on that branch.
4. Open a pull request from it to `checksig`. It lands by squash.

The squash commit is signed by GitHub. Upstream's authorship stays in upstream's history, not in ours.

## Open pull requests at the time of this change

- `rebased` to `checksig` (#20) carries 29 commits rebased onto a 2023 upstream. It is not merged. Redo it as above on the current upstream tag and close it.
- The Dependabot bump of `ecdsa` (#21) is not merged. Reopen or recreate it after the first update, so that it targets the new base.

## Decision for the maintainers

The alternative to the update path above is one branch per upstream version, each made the default branch in turn. It keeps each version's history intact, but changes the default branch at every update and breaks links and open pull requests.
