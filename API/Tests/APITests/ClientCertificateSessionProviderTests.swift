import XCTest
@testable import API

final class ClientCertificateSessionProviderTests: XCTestCase {
  func testNilReferenceReturnsSharedBaseSession() {
    let provider = ClientCertificateSessionProvider()

    let first = provider.session(
      for: nil,
      allowedHosts: [],
      discretionary: false
    )
    let second = provider.session(
      for: nil,
      allowedHosts: [],
      discretionary: false
    )

    XCTAssertTrue(first as AnyObject === second as AnyObject)
  }

  func testCertificateSessionIsCachedAndInvalidated() {
    let provider = ClientCertificateSessionProvider()
    let reference = ClientCertificateReference(
      id: "cert-1",
      displayName: "client",
      fingerprintSHA256: String(repeating: "a", count: 64),
      importedAt: Date()
    )

    let first = provider.session(
      for: reference,
      allowedHosts: ["example.com:443"],
      discretionary: false
    )
    let second = provider.session(
      for: reference,
      allowedHosts: ["example.com:443"],
      discretionary: false
    )

    XCTAssertTrue(first as AnyObject === second as AnyObject)

    provider.invalidate(certificateID: reference.id)

    let third = provider.session(
      for: reference,
      allowedHosts: ["example.com:443"],
      discretionary: false
    )

    XCTAssertFalse(first as AnyObject === third as AnyObject)
  }
}
