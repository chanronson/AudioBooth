import XCTest
@testable import API

final class ClientCertificateImportCoordinatorTests: XCTestCase {
  private final class FakeStore: ClientCertificateStoring, @unchecked Sendable {
    var saved: StoredClientCertificate?

    func save(_ certificate: StoredClientCertificate) throws {
      saved = certificate
    }

    func load(id: String) -> StoredClientCertificate? {
      saved?.reference.id == id ? saved : nil
    }

    func delete(id: String) {
      if saved?.reference.id == id {
        saved = nil
      }
    }
  }

  func testCommitImportsAndStoresCertificate() throws {
    let store = FakeStore()
    let expected = StoredClientCertificate(
      reference: ClientCertificateReference(
        id: "cert-1",
        displayName: "client",
        fingerprintSHA256: String(repeating: "a", count: 64),
        importedAt: Date()
      ),
      p12Data: Data([1]),
      password: "test"
    )
    let coordinator = ClientCertificateImportCoordinator(
      store: store,
      importer: { _, _, _ in expected }
    )

    let pending = coordinator.prepare(data: Data([1]), displayName: "client")
    let reference = try coordinator.commit(pending, password: "test")

    XCTAssertEqual(reference, expected.reference)
    XCTAssertEqual(store.saved?.reference, expected.reference)
  }

  func testCommitFailureStoresNothing() {
    let store = FakeStore()
    let coordinator = ClientCertificateImportCoordinator(
      store: store,
      importer: { _, _, _ in throw ClientCertificateImportError.wrongPassword }
    )

    let pending = coordinator.prepare(data: Data([1]), displayName: "client")

    XCTAssertThrowsError(try coordinator.commit(pending, password: "wrong"))
    XCTAssertNil(store.saved)
  }

  func testRemoveDeletesStoredCertificate() throws {
    let store = FakeStore()
    let reference = ClientCertificateReference(
      id: "cert-1",
      displayName: "client",
      fingerprintSHA256: String(repeating: "a", count: 64),
      importedAt: Date()
    )
    try store.save(
      StoredClientCertificate(
        reference: reference,
        p12Data: Data([1]),
        password: "test"
      )
    )
    let coordinator = ClientCertificateImportCoordinator(store: store)

    coordinator.remove(reference)

    XCTAssertNil(store.saved)
  }
}
