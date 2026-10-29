import Foundation
import SimpleKeychain

protocol ClientCertificateKeychain: Sendable {
  func set(_ data: Data, forKey key: String) throws
  func data(forKey key: String) throws -> Data?
  func delete(forKey key: String) throws
}

public protocol ClientCertificateStoring: Sendable {
  func save(_ certificate: StoredClientCertificate) throws
  func load(id: String) -> StoredClientCertificate?
  func delete(id: String)
}

struct SimpleKeychainBackend: ClientCertificateKeychain {
  private let keychain = SimpleKeychain(
    service: "me.jgrenier.AudioBS.client-certificate",
    accessibility: .afterFirstUnlockThisDeviceOnly
  )

  func set(_ data: Data, forKey key: String) throws {
    try keychain.set(data, forKey: key)
  }

  func data(forKey key: String) throws -> Data? {
    try? keychain.data(forKey: key)
  }

  func delete(forKey key: String) throws {
    try? keychain.deleteItem(forKey: key)
  }
}

public final class ClientCertificateStore: ClientCertificateStoring, @unchecked Sendable {
  public static let shared = ClientCertificateStore()

  private let keychain: any ClientCertificateKeychain
  private let lock = NSLock()
  private let encoder = JSONEncoder()
  private let decoder = JSONDecoder()

  init(keychain: any ClientCertificateKeychain = SimpleKeychainBackend()) {
    self.keychain = keychain
  }

  public func save(_ certificate: StoredClientCertificate) throws {
    lock.lock()
    defer { lock.unlock() }
    try keychain.set(try encoder.encode(certificate), forKey: certificate.reference.id)
  }

  public func load(id: String) -> StoredClientCertificate? {
    lock.lock()
    defer { lock.unlock() }
    guard let data = try? keychain.data(forKey: id) else { return nil }
    return try? decoder.decode(StoredClientCertificate.self, from: data)
  }

  public func delete(id: String) {
    lock.lock()
    defer { lock.unlock() }
    try? keychain.delete(forKey: id)
  }
}
