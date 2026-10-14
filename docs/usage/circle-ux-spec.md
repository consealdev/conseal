# Circle UX Specification

Required UI moments for the `conseal/circle` device-registration ceremony.

Visual treatment is app-defined. The four moments below are **required** — skipping any of them is a security regression, not a design choice.

---

## Overview

The ceremony involves two parties across two devices:

```
New device                   Trusted device (already in circle)
──────────                   ──────────────────────────────────
1. Request initiated →
                             2. Approval request received
                             3. User confirms approval →
4. Join complete or failed ←
```

---

## Moment 1 — New device: request initiated

**Trigger:** `createJoinRequest()` has been called; the join request has been submitted to the backend.

**User's situation:** the user is on the new device waiting for approval. They need to know what to do next.

### Required elements

| Element | Requirement |
|---------|-------------|
| Status indicator | Make clear that a request is pending and that action is needed on another device |
| **Verification code** | Display prominently (large text, high contrast). Format: `XX-XX-XX-XX`. Label it clearly — e.g. "Verification code" or "Security code" |
| Instructions | Tell the user to open the app on an existing device and look for an approval request there |
| Expiry | Show the remaining time or expiry time. When the request expires, transition to the failed state (Moment 4) automatically |

### Verification code prominence

The verification code is the **primary defence against server-side MITM**. It must not be buried in small text or hidden behind a tap. Treat it with the same weight as a 2FA code:

- Minimum font size: 24pt or equivalent
- High contrast against background
- Not truncated, not scrolled off screen by default

### Polling

While waiting, the new device polls `GET /circle/devices/join/:challengeId`. On `"authorized"`, call `finalizeJoin()` immediately and transition to Moment 4.

---

## Moment 2 — Trusted device: approval request received

**Trigger:** the backend has received a join request for the user's circle. The trusted device must notify the user.

**User's situation:** they may not be actively using the app. The notification must reach them.

### Required elements

| Element | Requirement |
|---------|-------------|
| Explicit notification | Push notification, in-app badge, email, or polling UI. Silent background approval is not permitted |
| Non-dismissable until acted on | Do not auto-dismiss or let the notification expire silently. The user must explicitly respond |

### Notification copy (example)

> "A new device is requesting access to your account. Tap to review."

Do not include the verification code in the notification — it is shown in Moment 3 after the user opens the app.

---

## Moment 3 — Trusted device: user confirms approval

**Trigger:** the user has tapped the notification / opened the approval UI.

**User's situation:** they must decide whether to approve a join request. This screen is the last gate before the AEK is transferred.

### Required elements

| Element | Requirement |
|---------|-------------|
| Device info | Show device name, platform, and request timestamp |
| **Verification code** | Display prominently. Instruct the user to confirm it matches what is shown on the new device |
| Confirmation prompt | Explicit question, e.g. "Does this code match the code shown on your new device?" |
| Approve and Deny buttons | Both clearly labelled. Deny must be easy to reach — not buried |
| Request age | Show how long ago the request was created. If older than 5 minutes, disable Approve (this is also enforced by `authorizeJoin()`) |

### Verification code confirmation is mandatory

A tap on "Approve" without displaying and confirming the verification code is insufficient. The confirmation step must be **visible and explicit** — not a silent checkbox or a modal that auto-dismisses.

**Correct:** "The verification code on your new device should show **A3-K9-F2**. Does it match?"

**Not sufficient:** A single "Approve" button on a screen that shows only the device name.

### After approval

Call `authorizeJoin()`. On success, post the `sealedAEK` to `POST /circle/devices/join/:challengeId/authorize`. Show a brief confirmation ("Approved — the new device will now sync your encrypted data").

---

## Moment 4 — New device: join complete or failed

**Trigger:** `finalizeJoin()` has completed, or the challenge expired or was denied.

**User's situation:** they need to know the outcome and what to do next.

### Success state

| Element | Requirement |
|---------|-------------|
| Clear success indicator | "You're connected" / "Sync active" — avoid vague language |
| What it means | Brief explanation: the device can now read and write encrypted data in sync with other devices |
| Next action | Navigate to the main app screen or close the modal |

### Failure states

Each failure reason must have a distinct message and a clear next action.

| Status | Message | Next action |
|--------|---------|-------------|
| `expired` | "The request timed out (5 minutes). Start over to try again." | Restart ceremony |
| `denied` | "The request was denied on your other device." | Contact support or restart |
| `error` (network, crypto) | "Something went wrong. Please try again." | Retry or restart |

Do not show a generic "something went wrong" for `expired` or `denied` — the user needs to know whether to retry or investigate.

---

## Device management UI (recommended, not required by the ceremony)

Once a device is in the circle, the app should offer a management screen:

### Device list

- Name and platform for each device
- Registration date
- Visual indicator of the current device ("This device")
- Remove button per device (triggers `DELETE /circle/devices/:deviceId`)

### Device removal confirmation

Removing a device is irreversible without a new ceremony. Show a confirmation dialog:

> "Remove [device name]? This device will immediately lose access to your encrypted data. This cannot be undone."

Do not use destructive phrasing like "delete" for the device itself — "remove from circle" is clearer.

---

## Accessibility and security notes

- Verification codes must be selectable or copyable so users can compare across devices without manually reading each character
- Do not auto-approve on touch (Touch ID, Face ID) without presenting the verification code — biometric confirmation is for authentication, not for bypassing out-of-band verification
- Screen recording / screenshot blocking is recommended on verification code screens if the platform supports it (e.g. `FLAG_SECURE` on Android)
