import Foundation

public final class ClientCertificateRegistry: @unchecked Sendable {
  public static let shared = ClientCertificateRegistry()

  private let lock = NSLock()
  private var entries: [String: ClientCertificateReference] = [:]

  public init() {}

  public func update(
    endpoints: Set<String>,
    reference: ClientCertificateReference?
  ) {
    lock.lock()
    defer { lock.unlock() }

    entries.removeAll()

    if let reference {
      for endpoint in endpoints {
        entries[endpoint] = reference
      }
    }
  }

  public func reference(forEndpoint endpoint: String) -> ClientCertificateReference? {
    lock.lock()
    defer { lock.unlock() }
    return entries[endpoint]
  }
}
