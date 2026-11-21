# Conseal

Conseal is end-to-end encryption for web apps. Data is sealed on the user's device before it leaves it. The server stores
and orders ciphertext it can't open. A key reaches a new device only when the user approves it on a device that already
holds it, and merging runs on the client, on plaintext.

Conseal runs in your app: a library in the browser and a package in your ASP.NET Core backend. There is no hosted service.

## What an app gets

| Part | What it does |
|---|---|
| Sealing | Encrypts and decrypts data on the device with AES-256-GCM, and wraps keys under a passphrase |
| The circle | Shares the user's key between their devices. A new device joins when the user approves it on one that already holds the key, after comparing a verification code on both |
| Recovery | A 24-word recovery phrase restores the key when every device is lost |
| Channels | Shares a key between users: an invitee gets it after a member approves, with a verification code on both screens |
| Sync | Saves records on the device, seals and pushes what changed, pulls what the other devices wrote, and merges it on the client. Files go in blobs |
| Screens | The circle's setup, unlock, join, approval and device list, as Lit components |

## How it works

```
Browser                            Your backend                     Storage
-------                            ------------                     -------
CircleClient, SyncEngine     ->    ConsealDev.Conseal         ->    DynamoDB: ciphertext, wrapped keys
seal, open and merge         <-    sync and circle routes           S3: sealed blobs
```

The browser seals each record under a key that only the user's devices hold, and sends ciphertext. The backend orders what
it is sent and answers pulls. It holds wrapped keys and public keys, and nothing that opens a record. A blob goes from the
browser to S3 through a URL the backend presigns, so its bytes never pass through the backend.

## Contract

The routes the client calls and the backend serves are in [`spec/`](spec), as OpenAPI: `openapi.yaml` for sync and
`circle.yaml` for the circle. Both packages are built to it, and so is a backend in another language.
[`threat-model.md`](threat-model.md) says what Conseal protects, against whom, and what it relies on.

## Packages

### Conseal for JavaScript

[github.com/consealdev/conseal-js](https://github.com/consealdev/conseal-js)  -  npm package `@consealdev/conseal`

```bash
npm install @consealdev/conseal
```

Its root is the crypto core, `@consealdev/conseal/sync` has the circle client and the sync engine, and
`@consealdev/conseal/ui` has the screens. The first device creates the circle, and every record is sealed before it leaves
the device:

```ts
import {
    CircleClient, FetchCircleTransport, FetchSyncTransport, MemoryRecordStore,
    SyncEngine, defineCollections, newRecordId,
} from '@consealdev/conseal/sync';

type Notes = { notes: { title: string } };

const circle = new CircleClient({ transport: new FetchCircleTransport({ baseUrl: '/api/circle' }) });
const { mnemonic } = await circle.setup(passphrase);   // show the mnemonic once, and never store it

const sync = new SyncEngine<Notes>({
    collections: defineCollections<Notes>({ notes: { id: '7f3a9c21', schemaVersion: 1 } }),
    transport: new FetchSyncTransport({ baseUrl: '/api/sync' }),
    store: new MemoryRecordStore(),   // the app's own RecordStore in production
    keyring: circle,
});

await sync.save('notes', newRecordId(), { title: 'groceries' });
await sync.sync();
```

### Conseal for ASP.NET Core

[github.com/consealdev/conseal-dotnet](https://github.com/consealdev/conseal-dotnet)  -  NuGet package `ConsealDev.Conseal`  -  .NET 10

```bash
dotnet add package ConsealDev.Conseal
```

The settings go in `appsettings.json`, under `ConsealSync`: `CursorSigningKey`, base64 of at least 32 random bytes, such as
`openssl rand -base64 32`, and `Collections`, the ids from the client's registry. Register a store and map the routes:

```csharp
builder.Services
    .AddConsealSync(builder.Configuration)      // reads the ConsealSync section
    .AddDynamoStores(o => o.TablePrefix = "myapp-");

app.MapConsealSyncRoutes("sync");
app.MapConsealCircleRoutes("circle");
```

Every route requires an authenticated user, from the app's own sign-in.

## Docs

[conseal.dev/docs](https://conseal.dev/docs/)

---

The spec is licensed under the MIT License. See [spec/LICENSE](spec/LICENSE) for full terms. conseal-js and conseal-dotnet
are licensed under the GNU Affero General Public License v3.0 or the Conseal Commercial License: see their repositories.
