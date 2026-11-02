import Foundation

public struct ClientCertificateReference: Codable, Sendable, Equatable {
  public let id: String
  public let displayName: String
  public let fingerprintSHA256: String
  public let importedAt: Date

  public init(
    id: String,
    displayName: String,
    fingerprintSHA256: String,
    importedAt: Date
  ) {
    self.id = id
    self.displayName = displayName
    self.fingerprintSHA256 = fingerprintSHA256
    self.importedAt = importedAt
  }
}

public struct StoredClientCertificate: Codable, Sendable {
  public let reference: ClientCertificateReference
  public let p12Data: Data
  public let password: String

  public init(
    reference: ClientCertificateReference,
    p12Data: Data,
    password: String
  ) {
    self.reference = reference
    self.p12Data = p12Data
    self.password = password
  }
}
