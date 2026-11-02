import XCTest
@testable import API

final class ClientCertificateCredentialTests: XCTestCase {
  private func fixture() throws -> Data {
    let url = try XCTUnwrap(
      Bundle.module.url(
        forResource: "client",
        withExtension: "p12",
        subdirectory: "Fixtures"
      )
    )
    return try Data(contentsOf: url)
  }

  func testCredentialIsCreatedForStoredCertificate() throws {
    let keychain = InMemoryClientCertificateKeychain()
    let store = ClientCertificateStore(keychain: keychain)
    let stored = try ClientCertificateImporter.importPKCS12(
      data: fixture(),
      password: "test",
      displayName: "client"
    )
    try store.save(stored)

    let credential = ClientCertificateCredentialProvider.credential(
      for: stored.reference,
      store: store
    )

    XCTAssertNotNil(credential)
    XCTAssertEqual(credential?.persistence, .forSession)
  }

  func testCredentialIsNilForMissingCertificate() {
    let store = ClientCertificateStore(
      keychain: InMemoryClientCertificateKeychain()
    )
    let reference = ClientCertificateReference(
      id: "missing",
      displayName: "client",
      fingerprintSHA256: String(repeating: "a", count: 64),
      importedAt: Date()
    )

    XCTAssertNil(
      ClientCertificateCredentialProvider.credential(
        for: reference,
        store: store
      )
    )
  }

  func testChallengeHandlerRejectsUnrelatedHost() {
    XCTAssertFalse(
      ClientCertificateChallengeHandler.isAllowed(
        host: "other.com",
        port: 443,
        allowedHosts: ["example.com:443"]
      )
    )
    XCTAssertTrue(
      ClientCertificateChallengeHandler.isAllowed(
        host: "example.com",
        port: 443,
        allowedHosts: ["example.com:443"]
      )
    )
  }
}
