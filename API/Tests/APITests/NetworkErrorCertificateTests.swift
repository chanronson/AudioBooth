import XCTest
@testable import API

final class NetworkErrorCertificateTests: XCTestCase {
  func testClientCertificateRequiredIsMapped() {
    let mapped = NetworkError.map(URLError(.clientCertificateRequired))

    guard case NetworkError.clientCertificateRequired = mapped else {
      return XCTFail("Expected clientCertificateRequired")
    }
  }

  func testClientCertificateRejectedIsMapped() {
    let mapped = NetworkError.map(URLError(.clientCertificateRejected))

    guard case NetworkError.clientCertificateRejected = mapped else {
      return XCTFail("Expected clientCertificateRejected")
    }
  }
}
