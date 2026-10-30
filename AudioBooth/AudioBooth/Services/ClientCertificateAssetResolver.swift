import API
import AVFoundation
import Foundation

enum ClientCertificateAssetResolver {
  nonisolated static func asset(for url: URL) async -> AVURLAsset {
    let configuration: (
      reference: ClientCertificateReference?,
      headers: [String: String],
      allowedHosts: Set<String>
    ) = await MainActor.run {
      let server = Audiobookshelf.shared.authentication.server
      return (
        reference: server?.clientCertificate,
        headers: server?.customHeaders ?? [:],
        allowedHosts: server?.certificateAllowedHosts ?? []
      )
    }

    if !url.isFileURL, let reference = configuration.reference {
      return ClientCertificateAsset(
        url: url,
        headers: configuration.headers,
        reference: reference,
        allowedHosts: configuration.allowedHosts
      )
    }
    return AVURLAsset(url: url)
  }
}
