# mTLS Client Certificate Support

## Summary

Add per-server TLS client-certificate authentication (mTLS) to AudioBooth on iOS, iPadOS, and watchOS. A user imports a PKCS#12 file (`.p12` or `.pfx`) and its password. AudioBooth stores the identity in the Keychain and presents it when the configured Audiobookshelf server or its reverse proxy requests a client certificate.

## Goals

- Import, validate, store, replace, and remove one client certificate per server connection.
- Present the certificate for all main-app and watch-app HTTP traffic to that server: API calls, image loading, downloads, direct file downloads, and the OIDC bootstrap request.
- Support Apple Watch traffic by syncing the certificate from the paired iPhone.
- Keep normal server-certificate validation unchanged.
- Show clear, actionable errors when a certificate is missing, invalid, or rejected.
- Never write the PKCS#12 password or private key to logs or plain preferences.

## Non-Goals

- No option to trust an invalid or self-signed server certificate.
- No certificate generation, export, or certificate-authority management.
- No support for multiple certificates on one server connection.
- No in-app browser replacement for OIDC. The system browser cannot use an app-imported identity.
- No widget-extension networking changes. Widget cover loading keeps its current behavior.
- No Android, web, or desktop client work.

## User Experience

### New server setup

`ServerView` shows a "Client Certificate" row in the "Server Configuration" section. The row is available before authentication. The user can import a certificate before or after entering the server URL. The certificate is used for the `/status` request and for login requests.

### Existing server

`ServerView` shows a "Client Certificate" row in the "Advanced" section. The row opens the same certificate screen.

### Certificate screen

The screen shows:

- Status: "Not configured" or the certificate display name.
- SHA-256 fingerprint in uppercase colon-separated groups.
- Import date.
- "Import Certificate" or "Replace Certificate" action.
- "Remove Certificate" destructive action with confirmation.
- A note that OIDC sign-in uses the system browser and needs a system-installed certificate profile.

### Import flow

1. The user taps "Import Certificate".
2. A system file picker accepts `.p12` and `.pfx`.
3. A password sheet asks for the PKCS#12 password.
4. AudioBooth validates the file and password.
5. On success, the certificate is stored and the screen shows its details.
6. On failure, a toast explains the problem and nothing is stored.

The display name is the selected filename without its extension. If that is empty, use the leaf certificate common name.

`ClientCertificateImportCoordinator` owns the non-UI import state:

```swift
public struct PendingClientCertificateImport: Sendable {
  public let data: Data
  public let displayName: String
}

public final class ClientCertificateImportCoordinator {
  public init(
    store: any ClientCertificateStoring = ClientCertificateStore.shared,
    importer: @escaping (Data, String, String) throws -> StoredClientCertificate
      = ClientCertificateImporter.importPKCS12
  )
  public func prepare(data: Data, displayName: String) -> PendingClientCertificateImport
  public func commit(
    _ pending: PendingClientCertificateImport,
    password: String
  ) throws -> ClientCertificateReference
  public func remove(_ reference: ClientCertificateReference?)
}
```

## Data Model

### `ClientCertificateReference`

```swift
public struct ClientCertificateReference: Codable, Sendable, Equatable {
  public let id: String
  public let displayName: String
  public let fingerprintSHA256: String
  public let importedAt: Date
}
```

- `id` is a UUID string generated at import time.
- `fingerprintSHA256` is lowercase hexadecimal without separators.
- The reference contains no secret material.

### `Connection`

`Connection` gains an optional `clientCertificate: ClientCertificateReference?` property. Decoding a connection without this key produces `nil`. Existing stored connections continue to load.

### `Server`

`Server` gains `clientCertificate: ClientCertificateReference?` and initializes it from `Connection`. It also gains `certificateAllowedHosts: Set<String>` computed from `baseURL` and `alternativeURL`.

### `StoredClientCertificate`

```swift
public struct StoredClientCertificate: Codable, Sendable {
  public let reference: ClientCertificateReference
  public let p12Data: Data
  public let password: String
}
```

This value is stored only in the Keychain. It is never encoded into `Connection`, `UserDefaults`, or logs.

## Keychain Storage

`ClientCertificateStore` stores each `StoredClientCertificate` as JSON data.

- Keychain service: `me.jgrenier.AudioBS.client-certificate`
- Keychain account: `reference.id`
- Accessibility: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
- Uses `SimpleKeychain` with the same service name.

API:

```swift
public final class ClientCertificateStore: @unchecked Sendable {
  public static let shared: ClientCertificateStore
  public func save(_ certificate: StoredClientCertificate) throws
  public func load(id: String) -> StoredClientCertificate?
  public func delete(id: String)
}
```

The store has an internal initializer that accepts a `ClientCertificateKeychain` protocol. Production uses `SimpleKeychain`; tests use an in-memory implementation with `@testable import API`.

The public `ClientCertificateStoring` protocol exposes `save`, `load`, and `delete`. `ClientCertificateStore` conforms to it. This protocol lets the import coordinator and app view model use a test double.

Replacing a certificate deletes the previous Keychain item after the new item is saved. Removing a server deletes its certificate item.

## Import and Validation

`ClientCertificateImporter` validates and converts a PKCS#12 file without persisting it.

```swift
public enum ClientCertificateImportError: LocalizedError {
  case tooLarge
  case invalidFormat
  case wrongPassword
  case missingIdentity
}

public enum ClientCertificateImporter {
  public static let maximumFileSize = 1_048_576

  public static func importPKCS12(
    data: Data,
    password: String,
    displayName: String
  ) throws -> StoredClientCertificate
}
```

Rules:

- Reject data larger than 1 MB with `.tooLarge`.
- Reject malformed PKCS#12 data with `.invalidFormat`.
- Reject a wrong password with `.wrongPassword`.
- Require exactly one `SecIdentity`; otherwise throw `.missingIdentity`.
- Compute SHA-256 from the leaf certificate DER data.
- Return a `StoredClientCertificate` with a new UUID.

## Network Challenge Handling

### Allowed hosts

A certificate is allowed only for the host and port of the server's primary URL and alternative URL. Normalize each endpoint as `host.lowercased():port`, where a missing port is 443 for HTTPS and 80 for HTTP.

This prevents the certificate from being sent to an unrelated host after a redirect.

### `ClientCertificateCredentialProvider`

A public helper lets app-target delegates create a credential without exposing the internal challenge handler:

```swift
public enum ClientCertificateCredentialProvider {
  public static func credential(
    for reference: ClientCertificateReference,
    store: any ClientCertificateStoring = ClientCertificateStore.shared
  ) -> URLCredential?
}
```

It returns `nil` when the stored item is missing or cannot be imported.

A public factory creates a challenge delegate for `DataLoader` or custom sessions:

```swift
public enum ClientCertificateChallengeDelegate {
  public static func make(
    for reference: ClientCertificateReference,
    allowedHosts: Set<String>
  ) -> URLSessionDelegate
}
```

### `ClientCertificateChallengeHandler`

A `URLSessionTaskDelegate` that:

- Handles only `.clientCertificate` authentication challenges.
- If the challenge endpoint is in the allowed set, loads the stored PKCS#12, imports the identity, and responds with `URLCredential(identity:certificates:persistence: .forSession)`.
- If the certificate is missing or cannot be imported, cancels the challenge.
- For `.serverTrust` and all other challenge methods, calls the default handling.
- Never logs the PKCS#12 password, private key, or full certificate data.

### `ClientCertificateSessionProvider`

```swift
public final class ClientCertificateSessionProvider: @unchecked Sendable {
  public static let shared: ClientCertificateSessionProvider

  public func session(
    for reference: ClientCertificateReference?,
    allowedHosts: Set<String>,
    discretionary: Bool
  ) -> any URLSessionProtocol

  public func invalidate(certificateID: String)
}
```

- With no reference, returns the existing shared session.
- With a reference, returns a cached session whose delegate is a `ClientCertificateChallengeHandler`.
- The cache key includes the certificate ID, sorted allowed hosts, and the discretionary flag.
- `invalidate(certificateID:)` removes cached sessions after a certificate change or removal.
- On watchOS the session is a plain `URLSession`. On iOS and Mac Catalyst it is a `URLSessionProxy` with the same delegate.

### `ClientCertificateRegistry`

Background `URLSession` delegates cannot receive a per-request certificate reference. A shared registry maps active endpoints to the active server's certificate.

```swift
public final class ClientCertificateRegistry: @unchecked Sendable {
  public static let shared: ClientCertificateRegistry
  public func update(endpoints: Set<String>, reference: ClientCertificateReference?)
  public func reference(forEndpoint endpoint: String) -> ClientCertificateReference?
}
```

The registry is updated when the active server, its certificate, or its URLs change. It is used by the iOS and watchOS download managers.

## NetworkService Integration

`NetworkService` gains an optional `clientCertificate` parameter.

- When a `server` is present, use `server.clientCertificate`.
- When no server is present, use the explicitly supplied certificate. This covers new-server login and `/status`.
- Compute allowed hosts from the base URL and, when present, the server's alternative URL.
- Obtain the session from `ClientCertificateSessionProvider`.

`NetworkService` maps these URL errors to a new `NetworkError.clientCertificateRequired` case:

- `NSURLErrorClientCertificateRequired` (`-1206`)
- `NSURLErrorClientCertificateRejected` (`-1205`)

The error message must tell the user to open Server > Client Certificate and import a valid certificate.

## AuthenticationService Integration

- `login`, `loginWithOIDC`, and `loginWithAPIKey` accept an optional `clientCertificate: ClientCertificateReference?`.
- The supplied reference is used for the login request and then attached to the new or updated connection.
- `upsertConnection` accepts and stores the reference.
- `updateClientCertificate(_ serverID: String, reference: ClientCertificateReference?)` updates the server and connection, refreshes image loading, and updates the registry.
- `removeServer` deletes the certificate from the Keychain.
- `switchToServer` updates the registry and image pipeline.

## Image Loading

`ImagePipeline.audioBooth` and `ImagePipeline.watch` accept an optional `ClientCertificateReference` and allowed hosts. When present, the `DataLoader` delegate is a `ClientCertificateChallengeHandler`. All call sites pass the active server's certificate.

## Direct File Downloads

Three app flows use `URLSession.shared` directly:

- `NarrationProbe` range requests.
- `BookShareItem` ebook download.
- `EbookReaderViewModel` temporary file download.

Add an app-level `ServerSession` helper that returns a certificate-aware session for the active server. Replace these three `URLSession.shared` calls with that helper. These flows must keep their current progress and error behavior.

## Downloads

### iOS/iPadOS

`DownloadSessionDelegate` handles client-certificate challenges through `ClientCertificateRegistry`. The registry is updated when the active server changes.

### watchOS

The watch download manager does the same with its own registry state.

## OIDC

The OIDC bootstrap request uses a session with the pending or active certificate. The system-browser step (`ASWebAuthenticationSession`) cannot use an app-imported identity. The certificate screen and documentation state that OIDC users need a system-installed certificate profile.

## Apple Watch Sync

- `Connection` carries the `ClientCertificateReference`.
- The iPhone sends the reference in the WatchConnectivity application context.
- When the reference changes, the iPhone sends the PKCS#12 data with `transferFile`. Metadata contains the command, certificate ID, display name, fingerprint, and password.
- The watch stores the received value in its own Keychain with the same store API.
- If the watch has a reference but no stored certificate, it sends a `requestClientCertificate` message. The iPhone resends the file.
- When the reference becomes `nil`, the watch deletes the previous certificate.
- The watch uses its active server's certificate for API calls, image loading, and downloads.

WatchConnectivity traffic is encrypted by the system. The watch must not write the password to `UserDefaults` or logs.

## UI Model

`ClientCertificateViewModel` owns:

- `reference: ClientCertificateReference?`
- `isImporting: Bool`
- `errorMessage: String?`
- `pendingPasswordPrompt: PendingImport?`
- `importFile(at url: URL)`
- `submitPassword(_ password: String)`
- `removeCertificate()`
- `onCertificateChanged: (ClientCertificateReference?) -> Void`

The model reads and writes through `ClientCertificateStore` and calls the callback after a successful change. The view does not touch the Keychain directly.

## Error Handling

| Condition | Behavior |
|---|---|
| File is larger than 1 MB | Toast: certificate file is too large |
| File is not PKCS#12 | Toast: certificate format is not supported |
| Password is wrong | Toast: certificate password is incorrect |
| No identity in file | Toast: certificate has no private key |
| Server requests a certificate but none is configured | Network error with Server > Client Certificate guidance |
| Configured certificate is rejected | Network error with certificate guidance |
| Certificate removed while active | Cached sessions invalidated; next request shows the missing-certificate error |
| Watch certificate is missing | Watch requests a resend; if unavailable, download shows a certificate error |

## Security Requirements

- Store PKCS#12 data and password only in the Keychain.
- Use `afterFirstUnlockThisDeviceOnly`.
- Do not put certificate secrets in `Connection`, `UserDefaults`, logs, analytics, or crash reports.
- Present the certificate only to allowed server endpoints.
- Keep server-trust validation unchanged.
- Delete the Keychain item when the server is removed or the certificate is replaced.
- Reject files larger than 1 MB before parsing.

## Testing

### API package unit tests

- `Connection` decodes legacy data without a certificate.
- `ClientCertificateReference` round-trips through JSON.
- Importer accepts a valid fixture PKCS#12.
- Importer rejects a wrong password, invalid data, and oversized data.
- Importer computes a stable fingerprint.
- Store saves, loads, and deletes with an injected in-memory backend.
- Endpoint normalization handles default ports, explicit ports, and case.
- Allowed-host checks reject unrelated hosts.
- `NetworkError` maps `-1205` and `-1206` to the certificate message.

### Import coordinator unit tests

- `prepare` keeps the selected data and display name.
- `commit` imports a valid file, stores it, and returns the reference.
- A failed `commit` reports the import error and stores nothing.
- `remove` deletes the stored item.
- The coordinator never exposes the PKCS#12 password.

### Manual verification

- Add a server behind an mTLS reverse proxy with a valid `.p12`.
- Confirm `/status`, login, library load, cover images, and a download succeed.
- Confirm the same server fails with a clear message when the certificate is removed.
- Confirm OIDC still works when the device has a system certificate profile.
- Confirm the watch receives the certificate and can download a book.
- Confirm the certificate is not present in Pulse logs or `UserDefaults`.

## Migration

- Existing `Connection` records decode with `clientCertificate == nil`.
- No migration is required.
- Older watch app versions ignore the new optional `Connection` field.

## Documentation

Add a user-facing document that explains:

- How to create a `.p12` file.
- How to import and remove it.
- Which traffic uses it.
- The OIDC system-browser limitation.
- How watch sync works.
