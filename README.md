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
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability |

## Repository structure

```
conseal/                ← this repo
├── pages/              ← gitignored: a clone of consealdev/pages, the pages of conseal.dev
├── spec/               ← the wire contract
└── src/
    └── sdk/
        ├── js/         ← gitignored: a clone of consealdev/conseal-js
        └── dotnet/     ← gitignored: a clone of consealdev/conseal-dotnet
```

## Getting started

```sh
git clone https://github.com/consealdev/conseal
cd conseal
git clone https://github.com/consealdev/conseal-js src/sdk/js
git clone https://github.com/consealdev/conseal-dotnet src/sdk/dotnet
```

## License

Each part has its own. conseal-js and conseal-dotnet are dual-licensed under AGPL-3.0 and a commercial license. The
spec is [MIT](spec/LICENSE).
