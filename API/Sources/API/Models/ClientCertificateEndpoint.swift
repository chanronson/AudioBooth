import Foundation

public struct ClientCertificateEndpoint: Hashable, Sendable {
  public let key: String

  public init?(url: URL) {
    guard let host = url.host else { return nil }
    let defaultPort = url.scheme?.lowercased() == "http" ? 80 : 443
    self.init(host: host, port: url.port ?? defaultPort)
  }

  public init?(host: String, port: Int) {
    guard !host.isEmpty, port > 0 else { return nil }
    self.key = "\(host.lowercased()):\(port)"
  }
}
