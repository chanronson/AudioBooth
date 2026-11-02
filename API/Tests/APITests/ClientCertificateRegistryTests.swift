import XCTest
@testable import API

final class ClientCertificateRegistryTests: XCTestCase {
  private let reference = ClientCertificateReference(
    id: "cert-1",
    displayName: "client",
    fingerprintSHA256: String(repeating: "a", count: 64),
    importedAt: Date()
  )

  func testRegistryReturnsReferenceForConfiguredEndpoint() {
    let registry = ClientCertificateRegistry()

    registry.update(
      endpoints: ["example.com:443"],
      reference: reference
    )

    XCTAssertEqual(
      registry.reference(forEndpoint: "example.com:443"),
      reference
    )
    XCTAssertNil(registry.reference(forEndpoint: "other.com:443"))
  }

  func testRegistryClearsWhenReferenceIsNil() {
    let registry = ClientCertificateRegistry()
    registry.update(
      endpoints: ["example.com:443"],
      reference: reference
    )

    registry.update(endpoints: ["example.com:443"], reference: nil)

    XCTAssertNil(registry.reference(forEndpoint: "example.com:443"))
  }
}
