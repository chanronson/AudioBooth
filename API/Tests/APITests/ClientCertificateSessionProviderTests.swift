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

  private func makeReference(_ id: String) -> ClientCertificateReference {
    ClientCertificateReference(
      id: id,
      displayName: "client",
      fingerprintSHA256: String(repeating: "a", count: 64),
      importedAt: Date()
    )
  }

  func testOldestSessionIsEvictedWhenCacheOverflows() {
    let provider = ClientCertificateSessionProvider()
    let reference = makeReference("cert-1")

    let hostSets: [Set<String>] = (0..<9).map {
      ["host\($0).example.com:443"]
    }
    let first = provider.downloadSession(for: reference, allowedHosts: hostSets[0])

    for hosts in hostSets.dropFirst() {
      _ = provider.downloadSession(for: reference, allowedHosts: hosts)
    }

    XCTAssertEqual(provider.cachedSessionCount, 8)
    XCTAssertFalse(
      first as AnyObject === provider.downloadSession(for: reference, allowedHosts: hostSets[0]) as AnyObject
    )

    let mostRecent = provider.downloadSession(for: reference, allowedHosts: hostSets[8])
    XCTAssertTrue(
      mostRecent as AnyObject === provider.downloadSession(for: reference, allowedHosts: hostSets[8]) as AnyObject
    )
  }
}
