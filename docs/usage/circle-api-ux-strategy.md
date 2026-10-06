# Circle Backend & UI — Plug-and-Play Strategy

## Problem

The `circle-api-spec` and `circle-ux-spec` define what a correct integration looks like, but they require each adopter to:

1. Implement eight backend endpoints with non-trivial server rules (single-use challenges, `aekCommitment` immutability, TTL enforcement, device-scoped authorization).
2. Build UI that satisfies four mandatory security moments — any omission is a regression, not a design choice.

Every adopter who reads the spec and implements from scratch is an opportunity for a mistake. The strategy below closes that gap.

---

## Backend: .NET Minimal API Package

### Why .NET

.NET's `WebApplication` model in `Program.cs` is uniquely suited for a plug-and-play backend package:

- **No framework ambiguity.** There is one canonical way to add endpoints and middleware. Node, PHP, and Python each have competing frameworks (Express vs Fastify, Flask vs Django) with incompatible middleware pipelines — impossible to target without picking winners or maintaining multiple packages.
- **Middleware pipeline is standardized.** Auth, rate limiting, and CORS slot in via `UseXxx()` / `IMiddleware`. The package can document "add your auth middleware before `MapConsealCircle()`" and it works across every .NET project.
- **DI is first-class.** The storage adapter pattern fits naturally into the built-in container. Swapping DynamoDB for Postgres is a one-liner.
- **Single deployment target.** Azure, AWS Lambda (via Lambda Web Adapter), or a container — all from the same code and the same NuGet package.

### Integration surface

```csharp
// Program.cs
builder.Services.AddConsealCircle(options => {
    options.Storage = new DynamoCircleStore(builder.Configuration);
    options.ChallengeExpiry = TimeSpan.FromMinutes(5);
});

app.UseAuthentication(); // app's own auth middleware
app.MapConsealCircle();  // mounts all endpoints at /circle/**
```

`MapConsealCircle()` registers all eight endpoints defined in the API spec. The package enforces the server rules internally:

- `challengeId` is derived from `SHA-256(ephemeralPublicKey)` — not caller-supplied.
- `aekCommitment` is written once and rejected on overwrite.
- Challenge TTL is enforced server-side regardless of client-supplied `createdAt`.
- Consumed challenges return `410` on any subsequent authorize call.

### Storage adapter interface

The interface is intentionally narrow so custom adapters are cheap to write:

```csharp
public interface ICircleStore
{
    Task<Circle?> GetCircleAsync(string userId);
    Task UpsertDeviceAsync(string userId, Device device);
    Task DeleteDeviceAsync(string userId, string deviceId);
    Task<JoinChallenge?> GetChallengeAsync(string challengeId);
    Task UpsertChallengeAsync(JoinChallenge challenge);
}
```

**Shipped adapters:**

| Adapter | Package | Target audience |
|---------|---------|-----------------|
| DynamoDB | `Conseal.Circle.DynamoDB` | AWS-native, default |
| EF Core | `Conseal.Circle.EntityFramework` | SQL Server, Postgres, SQLite |

These two cover the majority of .NET production deployments.

---

## UI: Web Components (Lit) + React Wrappers

The UX spec defines four mandatory security moments. Skipping any one of them weakens the ceremony. Shipping off-the-shelf components makes the correct implementation the default.

### Why Lit

- **Framework-agnostic.** Web components work in React, Vue, Angular, Blazor, and plain HTML without adapter layers.
- **CSS custom properties** are the natural customization surface — no CSS-in-JS, no theme provider, no build-time configuration.
- Components can be published as a standard npm package consumed by any frontend.

### Component set

| Component | Covers |
|-----------|--------|
| `<conseal-join-pending>` | Moment 1 — verification code display, expiry countdown, polling trigger |
| `<conseal-join-request>` | Moment 2 & 3 — incoming request notification, device info, verification code, Approve/Deny |
| `<conseal-join-result>` | Moment 4 — success, expired, denied, and error states with distinct messages |

Example usage:

```html
<conseal-join-pending
  verification-code="A3-K9-F2"
  expires-at="2026-04-05T12:05:00Z"
  @expired="${handleExpired}"
  @authorized="${handleAuthorized}">
</conseal-join-pending>
```

Customization via CSS custom properties:

```css
conseal-join-pending {
  --conseal-code-font-size: 2rem;
  --conseal-code-color: #1a1a1a;
  --conseal-accent: #0057ff;
}
```

The components enforce the UX spec's non-negotiable requirements internally:
- Verification code is always rendered at minimum spec size and contrast.
- The approve action on `<conseal-join-request>` is only enabled after the verification code is displayed — a single-button flow that skips the code is not possible.
- `<conseal-join-result>` maps `expired`, `denied`, and `error` to distinct messages; a generic fallback is not provided.

React wrappers are auto-generated from the custom element manifest — no manual maintenance.

---

## Adoption tiers

| Tier | Backend | UI |
|------|---------|----|
| Minimal | NuGet package + DynamoDB adapter | Custom UI built against the UX spec |
| Standard | NuGet package + DynamoDB adapter | Lit web components, CSS-customized |
| Full | NuGet package + EF Core adapter | Lit components + React wrappers |

An adopter at the minimal tier gets correct server-side behavior with zero endpoint implementation work. An adopter at the full tier gets a working, spec-compliant ceremony end-to-end with only CSS and `Program.cs` configuration.

---

## Packaging

The core cryptographic library remains framework-agnostic. The backend and UI packages are published separately:

- `Conseal.Circle` — NuGet, the .NET minimal API package
- `Conseal.Circle.DynamoDB` — NuGet, DynamoDB storage adapter
- `Conseal.Circle.EntityFramework` — NuGet, EF Core storage adapter
- `@conseal/circle-components` — npm, Lit web components
- `@conseal/circle-react` — npm, React wrappers (generated)

This separation keeps the core library clean and lets adopters pull only what they need.

---

## What this does not solve

- **Authentication.** The package mounts endpoints that expect the request to already be authenticated. The app provides the auth middleware; the package provides the ceremony logic.
- **Push notifications.** The spec recommends push for Moment 2. The package supports polling via `GET /circle/pending-joins` out of the box. Push integration remains app-side.
- **AEK rotation.** Full cryptographic revocation after device removal is out of scope for v1. The package enforces lockout at the API level; key rotation is a separate ceremony.
