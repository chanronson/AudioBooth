import XCTest
@testable import API

final class ClientCertificateReferenceTests: XCTestCase {
  func testConnectionDecodesWithoutClientCertificate() throws {
    let json = """
    {"id":"server-1","serverURL":"https://example.com","token":"legacy-token","customHeaders":{}}
    """.data(using: .utf8)!

    let connection = try JSONDecoder().decode(Connection.self, from: json)

    XCTAssertNil(connection.clientCertificate)
  }

  func testConnectionRoundTripsClientCertificate() throws {
    let reference = ClientCertificateReference(
      id: "cert-1",
      displayName: "client",
      fingerprintSHA256: String(repeating: "a", count: 64),
      importedAt: Date(timeIntervalSince1970: 1_700_000_000)
    )
    let connection = Connection(
      id: "server-1",
      serverURL: URL(string: "https://example.com")!,
      token: .legacy(token: "legacy-token"),
      clientCertificate: reference
    )

    let decoded = try JSONDecoder().decode(
      Connection.self,
      from: JSONEncoder().encode(connection)
    )

    XCTAssertEqual(decoded.clientCertificate, reference)
  }

  func testEndpointUsesDefaultHTTPSPort() {
    let endpoint = ClientCertificateEndpoint(url: URL(string: "https://Example.com")!)

    XCTAssertEqual(endpoint?.key, "example.com:443")
  }

  func testEndpointUsesExplicitPort() {
    let endpoint = ClientCertificateEndpoint(url: URL(string: "https://alt.example.com:8443")!)

    XCTAssertEqual(endpoint?.key, "alt.example.com:8443")
  }

  func testEndpointUsesDefaultHTTPPort() {
    let endpoint = ClientCertificateEndpoint(url: URL(string: "http://example.com")!)

    XCTAssertEqual(endpoint?.key, "example.com:80")
  }

  @MainActor
  func testServerAllowedHostsIncludePrimaryAndAlternative() {
    let connection = Connection(
      serverURL: URL(string: "https://Example.com")!,
      token: .legacy(token: "legacy-token"),
      alternativeURL: URL(string: "https://alt.example.com:8443")!
    )

    let server = Server(connection: connection)

    XCTAssertEqual(server.certificateAllowedHosts, ["example.com:443", "alt.example.com:8443"])
  }
}
