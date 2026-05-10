# duetos-packages — repo template

Scaffold this directory into your `duetos-packages` GitHub repo
to get a Phase-7 package repository that `duet-pkg` can talk to.

## What's here

```
.
├── repo.toml                        ← the index `duet-pkg` fetches
├── keys/official.pub                ← your Ed25519 public key (PEM)
├── packages/
│   └── <name>-<version>-x86_64.tar.gz
│   └── <name>-<version>-x86_64.tar.gz.sig
└── .github/workflows/validate.yml   ← PR-time validator (calls validate.py)
```

## One-time setup

1. **Generate the signing keypair** (locally, NOT in CI):

   ```sh
   openssl genpkey -algorithm ed25519 -out duetos-official.pem
   openssl pkey -in duetos-official.pem -pubout -out keys/official.pub
   ```

   - `duetos-official.pem` → store offline (USB / password manager). **Never commit.**
   - `keys/official.pub` → commit.
   - Also add the private key's contents as the GitHub Actions
     secret `DUETOS_SIGNING_KEY` so future CI can sign tarballs
     automatically.

2. **Sign the initial repo.toml** locally:

   ```sh
   openssl pkeyutl -sign -inkey duetos-official.pem -rawin \
       -in repo.toml -out repo.toml.sig
   ```

   Commit `repo.toml` + `repo.toml.sig`. `duet-pkg repo add`
   fetches both.

3. **Enable GitHub Pages** on this repo (Settings → Pages →
   main → /root). The base URL becomes
   `https://<owner>.github.io/duetos-packages/`. Users
   register with:

   ```sh
   duet-pkg repo add https://<owner>.github.io/duetos-packages \
       --trust-key <sha256-fingerprint-of-keys/official.pub>
   ```

   The fingerprint is the SHA-256 of the raw 32-byte public key,
   lowercase hex. `duet-pkg-pack` prints it at the end of every
   `create` run.

## Adding a package

```sh
# 1. Build your binary (any way you like). Then:
duet-pkg-pack create \
    --name myapp \
    --version 1.0.0 \
    --bin path/to/myapp \
    --desc "What myapp does" \
    --license MIT \
    --key /secure/duetos-official.pem \
    --out-dir packages/

# 2. duet-pkg-pack drops two files into packages/ and prints
#    the [[packages]] block to paste into repo.toml. Paste it,
#    commit, open a PR.

# 3. On the PR, .github/workflows/validate.yml re-checks every
#    SHA-256 + every signature against keys/official.pub.

# 4. On merge, re-sign repo.toml (the new entry changed it) and
#    commit repo.toml.sig.
```

## Validating locally

```sh
python3 .github/workflows/validate.py
```
