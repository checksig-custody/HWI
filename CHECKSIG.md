# CheckSig fork

This is the CheckSig fork of [bitcoin-core/HWI](https://github.com/bitcoin-core/HWI).
Upstream's `README.md` is unchanged.

## Default branch

The default branch is `checksig`.

- A pull request targets `checksig` and lands by squash only.
- Every commit landing on `checksig` is signed. Our commits on a pull request branch are signed with our key.
- Upstream history is never merged into `checksig`.

## Taking an upstream update

1. Fetch the new tag from `bitcoin-core/HWI`. The `upstream` branch of this fork is not kept current.
2. Branch from that tag, for example `checksig-<tag>`.
3. Reapply our patches on it (cherry-pick or rebase), signed, and remove `.github/workflows`.
4. Run the fork's tests on that branch.
5. Record `checksig` as a parent with a signed `git merge -s ours origin/checksig`. A squash does not move the merge base, so without this each update pull request conflicts with `checksig`. With it, the squash lands exactly the tree that was tested.
6. Open a pull request from the branch to `checksig`. It lands by squash.

The squash commit is signed by GitHub. Upstream's authorship stays in upstream's history.

## Risks

- Upstream carries `.github/workflows`, and `checksig` has none. An update that keeps them starts GitHub Actions on every push.
- The fork has no release process and no GitHub releases.
