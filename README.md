# conseal-sync-spec

OpenAPI specification for Conseal Sync's wire contract: how a user's encrypted records move between their devices
through a server that can't read them. It defines the routes a sync backend serves, the record every client seals the
same way, and what a client does with each answer.

Any backend that satisfies this contract works with
[`conseal-sync-js`](https://github.com/consealdev/conseal-sync-js), and any client that follows it can read what
another client wrote, whatever language either is written in.

## What it covers

| Route | Does |
|-------|------|
| `GET /{prefix}` | The collections the server accepts, and the limits a client keeps to |
| `GET /{prefix}/{collectionId}` | Pull the records written since a cursor, in the server's order |
| `POST /{prefix}/{collectionId}` | Write a batch of records, or tombstone them, with optimistic concurrency |
| `POST`, `GET`, `DELETE /{prefix}/{collectionId}/{recordId}/blobs/{blobId}` | Presigned URLs to upload or download a blob, and deleting one. Optional |

Beside the routes, `info.description` in [`openapi.yaml`](openapi.yaml) holds the rules both sides depend on:

- **The record envelope:** a fresh DEK per write, wrapped under the user's AEK, and the AAD that binds each ciphertext
  to its collection and record
- **Order and consistency:** a server-assigned `seq` and a signed cursor, so a pull never skips a write and no client
  clock is involved
- **What a client does with each answer:** a `409` is a merge instruction, `400` and `413` are permanent, `429` and
  `5xx` are transient

[`threat-model.md`](threat-model.md) says what a server that follows the contract still learns, and what one that
doesn't can still do.

The circle's own routes, for joining devices, follow conseal's
[circle API spec](https://github.com/consealdev/conseal/blob/main/docs/usage/circle-api-spec.md) and aren't part of
this file.

## Usage

### Backend implementations

Use `openapi.yaml` as your build target. Three things are easy to get wrong:

- **`seq` in commit order, read consistently.** A pull must never skip a write, so the server assigns `seq` as writes
  commit and pages from a strongly consistent read. An eventually consistent index can show a later write before an
  earlier one.
- **`maxRecordBytes` from the storage backend.** It is the backend's item limit less the rest of the stored record,
  never a separate setting, so a record the server accepts is always one it can store.
- **No identity of its own.** The user id comes from the host app's sign-in, and every route acts on that user's data
  only.

### Clients

The envelope is what makes records readable across clients: seal and unseal exactly as `info.description` says,
including the AAD's bytes and the lowercase record id.

Nothing checks either side against this file yet.

### Local development

Clone into `spec/` inside the [`conseal-sync`](https://github.com/consealdev/conseal-sync) repo, beside the SDK repos:

```sh
git clone https://github.com/consealdev/conseal-sync-spec spec
```

Lint it with the rules in [`redocly.yaml`](redocly.yaml):

```sh
npx --yes @redocly/cli@2.54.3 lint openapi.yaml
```

## Route prefix

The route prefix is configurable per app (e.g. `/sync`). The spec uses `/{prefix}` as a placeholder.

## License

[MIT](LICENSE)
