# mTLS Client Certificates

## What mTLS Is

Mutual TLS (mTLS) is TLS authentication in two directions.

- The client checks the server certificate.
- The server checks a client certificate.

Use mTLS when your Audiobookshelf server or reverse proxy requires a client certificate. AudioBooth accepts one client certificate for each server connection.

## Create a PKCS#12 File

AudioBooth imports PKCS#12 files with the `.p12` or `.pfx` extension. The file must contain one certificate and its private key. The file must be 1 MB or smaller.

Use OpenSSL to create the file from a certificate and a private key:

```sh
openssl pkcs12 -export \
  -out client.p12 \
  -inkey client.key \
  -in client.crt
```

If your certificate needs an intermediate chain, add the chain file:

```sh
openssl pkcs12 -export \
  -out client.p12 \
  -inkey client.key \
  -in client.crt \
  -certfile chain.crt
```

OpenSSL asks for an export password. Use this password when you import the file in AudioBooth. Keep the file and the password in a safe location.

## Import a Certificate

### New Server

1. Open the AudioBooth server setup screen.
2. Enter the server URL.
3. Tap **Client Certificate**.
4. Tap **Import Certificate**.
5. Select the `.p12` or `.pfx` file.
6. Enter the PKCS#12 password.
7. Tap **Import**.

AudioBooth shows the certificate name, the SHA-256 fingerprint, and the import date after a successful import.

### Existing Server

1. Open the server settings.
2. Find the **Advanced** section.
3. Tap **Client Certificate**.
4. Tap **Import Certificate** or **Replace Certificate**.
5. Select the file and enter the password.

AudioBooth checks the file before it stores the certificate. If the import fails, AudioBooth shows an error and stores nothing.

## Replace a Certificate

1. Open **Server > Client Certificate**.
2. Tap **Replace Certificate**.
3. Select the new file and enter its password.

AudioBooth saves the new certificate and then deletes the previous certificate.

## Remove a Certificate

1. Open **Server > Client Certificate**.
2. Tap **Remove Certificate**.
3. Confirm the removal.

AudioBooth deletes the certificate from the Keychain. The server connection stays in the app. A server that requires a client certificate rejects later requests until you import a certificate again.

## Traffic That Uses the Certificate

AudioBooth sends the certificate to the host and port of the server URL and the alternative URL. AudioBooth does not send the certificate to unrelated hosts after a redirect.

The certificate applies to:

- Server status checks and login requests.
- Audiobookshelf API requests.
- Cover images in the app.
- Downloads and direct file downloads.
- Narration range requests and ebook downloads.
- The OIDC bootstrap request.

AudioBooth keeps normal server-certificate validation unchanged. The client certificate does not disable or weaken server trust checks.

## OIDC Limitation

OIDC sign-in uses the system browser. The system browser cannot use a certificate that you import in AudioBooth.

For OIDC with mTLS, install the client certificate as a system certificate profile on the device. The app-imported certificate is still necessary for the OIDC bootstrap request and normal app traffic.

## Apple Watch Sync

When you use Apple Watch with AudioBooth, the iPhone sends the active server certificate to the watch.

- The iPhone sends the certificate reference with the server connection data.
- When the certificate changes, the iPhone sends the PKCS#12 file and its password to the watch. The system encrypts WatchConnectivity traffic.
- The watch stores the certificate in its own Keychain.
- The watch uses the certificate for API calls, image loading, and downloads.

If the watch has a certificate reference but no stored certificate, the watch asks the iPhone to resend the file. If you remove the certificate on the iPhone, the watch deletes its copy.

## Security

AudioBooth stores the PKCS#12 data and the password only in the Keychain. The Keychain item uses the `afterFirstUnlockThisDeviceOnly` accessibility level.

AudioBooth does not store certificate secrets in connection data, preferences, logs, analytics, or crash reports.

Shared connection links contain the server URL, custom headers, an optional token, and an alias. Shared connection links do not contain the client certificate, its password, or its private key. Import the certificate separately on the other device.

## Troubleshooting

### Wrong Password

Error: **The certificate password is incorrect.**

Enter the PKCS#12 export password again. Check the keyboard language and the caps lock key. AudioBooth stores nothing after a failed import.

### Missing Private Key

Error: **The certificate file does not contain a private key.**

The file has a certificate but no private key. Create a new `.p12` file with the matching private key. Use the `openssl pkcs12 -export` command in this guide.

### Certificate Rejected

Error: **The server rejected the client certificate. Open Server > Client Certificate and check the certificate.**

Check these items:

- The certificate is current and not expired.
- The certificate belongs to the server trust chain.
- The reverse proxy accepts the certificate issuer.
- The fingerprint in AudioBooth matches the certificate on the server.

Replace the certificate if the server configuration changed.

### Certificate Required

Error: **This server requires a client certificate. Open Server > Client Certificate and import a valid certificate.**

The server requested a certificate but AudioBooth has no certificate for this connection. Import a certificate or check that the server URL matches the certificate host.

### Watch Resend

The watch asks the iPhone for the certificate when it has a reference but no stored certificate. Keep the iPhone and watch paired and near each other. Open the AudioBooth app on both devices.

If the watch still has no certificate, replace the certificate on the iPhone. This action triggers a new transfer to the watch.

### Certificate File Too Large

Error: **The certificate file is too large.**

The file is larger than 1 MB. Create a PKCS#12 file without extra certificates or unrelated data.

### Unsupported File Format

Error: **The certificate file is not a supported PKCS#12 file.**

Use a valid `.p12` or `.pfx` file. Check that the file is not damaged and that you selected the correct file.
