import CryptoKit
import Foundation
import Security

public enum ClientCertificateImportError: LocalizedError, Equatable {
  case tooLarge
  case invalidFormat
  case wrongPassword
  case missingIdentity

  public var errorDescription: String? {
    switch self {
    case .tooLarge:
      return "The certificate file is too large."
    case .invalidFormat:
      return "The certificate file is not a supported PKCS#12 file."
    case .wrongPassword:
      return "The certificate password is incorrect."
    case .missingIdentity:
      return "The certificate file does not contain a private key."
    }
  }
}

public enum ClientCertificateImporter {
  public static let maximumFileSize = 1_048_576

  public static func importPKCS12(
    data: Data,
    password: String,
    displayName: String
  ) throws -> StoredClientCertificate {
    guard data.count <= maximumFileSize else {
      throw ClientCertificateImportError.tooLarge
    }

    let options = [kSecImportExportPassphrase as String: password]
    var items: CFArray?
    let status = SecPKCS12Import(data as CFData, options as CFDictionary, &items)

    switch status {
    case errSecSuccess:
      break
    case errSecAuthFailed, errSecPkcs12VerifyFailure:
      throw ClientCertificateImportError.wrongPassword
    default:
      throw ClientCertificateImportError.invalidFormat
    }

    guard
      let entries = items as? [[String: Any]],
      let entry = entries.first,
      let identity = entry[kSecImportItemIdentity as String] as? SecIdentity
    else {
      throw ClientCertificateImportError.missingIdentity
    }

    var certificate: SecCertificate?
    guard
      SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
      let certificate
    else {
      throw ClientCertificateImportError.missingIdentity
    }

    let certificateData = SecCertificateCopyData(certificate) as Data
    let fingerprint = SHA256.hash(data: certificateData)
      .map { String(format: "%02x", $0) }
      .joined()

    let resolvedName =
      displayName.isEmpty
      ? (SecCertificateCopySubjectSummary(certificate) as String? ?? "Client Certificate")
      : displayName

    let reference = ClientCertificateReference(
      id: UUID().uuidString,
      displayName: resolvedName,
      fingerprintSHA256: fingerprint,
      importedAt: Date()
    )

    return StoredClientCertificate(
      reference: reference,
      p12Data: data,
      password: password
    )
  }
}
