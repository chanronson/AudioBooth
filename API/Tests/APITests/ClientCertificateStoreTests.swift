import XCTest
@testable import API

final class InMemoryClientCertificateKeychain: ClientCertificateKeychain {
  var storage: [String: Data] = [:]

  func set(_ data: Data, forKey key: String) throws {
    storage[key] = data
  }

  func data(forKey key: String) throws -> Data? {
    storage[key]
  }

  func delete(forKey key: String) throws {
    storage.removeValue(forKey: key)
  }
}

final class ClientCertificateStoreTests: XCTestCase {
  private func makeCertificate(id: String = "cert-1") -> StoredClientCertificate {
    StoredClientCertificate(
      reference: ClientCertificateReference(
        id: id,
        displayName: "client",
        fingerprintSHA256: String(repeating: "a", count: 64),
        importedAt: Date(timeIntervalSince1970: 1_700_000_000)
      ),
      p12Data: Data([1, 2, 3]),
      password: "test"
    )
  }

  func testSaveLoadAndDelete() throws {
    let keychain = InMemoryClientCertificateKeychain()
    let store = ClientCertificateStore(keychain: keychain)
    let certificate = makeCertificate()

    try store.save(certificate)

    XCTAssertEqual(store.load(id: "cert-1")?.reference, certificate.reference)
    XCTAssertEqual(store.load(id: "cert-1")?.p12Data, certificate.p12Data)

    store.delete(id: "cert-1")

    XCTAssertNil(store.load(id: "cert-1"))
  }

  func testSaveOverwritesExistingItem() throws {
    let keychain = InMemoryClientCertificateKeychain()
    let store = ClientCertificateStore(keychain: keychain)

    try store.save(makeCertificate(id: "cert-1"))

    let replacement = StoredClientCertificate(
      reference: ClientCertificateReference(
        id: "cert-1",
        displayName: "replacement",
        fingerprintSHA256: String(repeating: "b", count: 64),
        importedAt: Date()
      ),
      p12Data: Data([4, 5, 6]),
      password: "new"
    )
    try store.save(replacement)

    XCTAssertEqual(store.load(id: "cert-1")?.reference.displayName, "replacement")
  }
}
