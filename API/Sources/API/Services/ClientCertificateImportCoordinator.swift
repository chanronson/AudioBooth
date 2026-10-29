import Foundation

public struct PendingClientCertificateImport: Sendable {
  public let data: Data
  public let displayName: String

  public init(data: Data, displayName: String) {
    self.data = data
    self.displayName = displayName
  }
}

public final class ClientCertificateImportCoordinator {
  public typealias Importer =
    @Sendable (Data, String, String) throws -> StoredClientCertificate

  private let store: any ClientCertificateStoring
  private let importer: Importer

  public init(
    store: any ClientCertificateStoring = ClientCertificateStore.shared,
    importer: @escaping Importer = ClientCertificateImporter.importPKCS12
  ) {
    self.store = store
    self.importer = importer
  }

  public func prepare(data: Data, displayName: String) -> PendingClientCertificateImport {
    PendingClientCertificateImport(data: data, displayName: displayName)
  }

  public func commit(
    _ pending: PendingClientCertificateImport,
    password: String
  ) throws -> ClientCertificateReference {
    let certificate = try importer(
      pending.data,
      password,
      pending.displayName
    )
    try store.save(certificate)
    return certificate.reference
  }

  public func remove(_ reference: ClientCertificateReference?) {
    guard let reference else { return }
    store.delete(id: reference.id)
  }
}
