# conseal

End-to-end encrypted sync and sharing for web apps. Data is sealed on the user's device before it leaves it. The server
stores and orders ciphertext it can't open. Keys reach a new device only when the user approves it on one that already
holds them, and merging runs on the client, on plaintext.

This repo ties conseal's parts together: the wire contract, the threat model, and the repos below.

---

## Packages

| Package | Repo | Published as | Language |
|---------|------|--------------|----------|
| conseal-js | [`consealdev/conseal-js`](https://github.com/consealdev/conseal-js) | `@consealdev/conseal` (npm) | TypeScript |
| conseal-dotnet | [`consealdev/conseal-dotnet`](https://github.com/consealdev/conseal-dotnet) | `ConsealDev.Conseal` (NuGet) | C# / .NET |

`@consealdev/conseal` is the client. Its root is the crypto core on SubtleCrypto: the primitives, the circle that shares
a user's key between their devices, and channels that share a key between users. `@consealdev/conseal/sync` moves the
user's records between their devices, and `@consealdev/conseal/ui` has the circle ceremony's screens as Lit components.
`ConsealDev.Conseal` is a backend for ASP.NET Core. The spec in this repo is the contract between them, and what a
backend in another language is built to.

Versions of `@consealdev/conseal` up to 0.6.0 are the crypto core alone, published from this repo before it became
the umbrella.

## In this repo

| Path | Holds |
|------|-------|
| [`spec/`](spec) | The wire contract: the sync and circle routes, as OpenAPI |
| [`threat-model.md`](threat-model.md) | What conseal protects, against whom, and what it relies on |

The [security policy](https://github.com/consealdev/.github/blob/main/SECURITY.md) and the contributing guide live in
[`consealdev/.github`](https://github.com/consealdev/.github), for every conseal repo.

## Repository structure

```
conseal/                    ← this repo
├── spec/                   ← the wire contract
└── repos/                  ← gitignored: the other conseal repos
    ├── conseal-js/         ← a clone of consealdev/conseal-js
    ├── conseal-dotnet/     ← a clone of consealdev/conseal-dotnet
    ├── conseal-pages/      ← a clone of consealdev/pages, the pages of conseal.dev
    └── conseal-github/     ← a clone of consealdev/.github, the org's security policy and contributing guide
```

## Getting started

```sh
git clone https://github.com/consealdev/conseal
cd conseal
git clone https://github.com/consealdev/conseal-js repos/conseal-js
git clone https://github.com/consealdev/conseal-dotnet repos/conseal-dotnet
git clone https://github.com/consealdev/.github repos/conseal-github
```

## Issues

Report bugs and request features at [github.com/consealdev/conseal/issues](https://github.com/consealdev/conseal/issues),
the one tracker for conseal-js, conseal-dotnet and the spec. Questions go to
[Discussions](https://github.com/consealdev/conseal/discussions). Pull requests are not accepted. Report a vulnerability
privately, as the [security policy](https://github.com/consealdev/.github/blob/main/SECURITY.md) says, never in an issue.

## License

Each part has its own. conseal-js and conseal-dotnet are dual-licensed under AGPL-3.0 and a commercial license. The
spec is [MIT](spec/LICENSE). Commercial licensing questions go to license@conseal.dev.
