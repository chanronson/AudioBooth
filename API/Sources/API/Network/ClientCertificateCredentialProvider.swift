import Foundation
import Security

public enum ClientCertificateCredentialProvider {
  public static func credential(
    for reference: ClientCertificateReference,
    store: any ClientCertificateStoring = ClientCertificateStore.shared
  ) -> URLCredential? {
    guard let stored = store.load(id: reference.id) else { return nil }

    let options = [kSecImportExportPassphrase as String: stored.password]
    var items: CFArray?
    guard
      SecPKCS12Import(
        stored.p12Data as CFData,
        options as CFDictionary,
        &items
      ) == errSecSuccess,
      let entries = items as? [[String: Any]],
      let entry = entries.first,
      let identity = entry[kSecImportItemIdentity as String] as? SecIdentity
    else {
      return nil
    }

    var certificate: SecCertificate?
    guard
      SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
      let certificate
    else {
      return nil
    }

    let chain =
      entry[kSecImportItemCertChain as String] as? [SecCertificate]
      ?? [certificate]

    return URLCredential(
      identity: identity,
      certificates: chain,
      persistence: .forSession
    )
  }
}
