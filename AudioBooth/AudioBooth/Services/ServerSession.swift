import API
import Foundation
import Pulse

@MainActor
enum ServerSession {
  static func current(discretionary: Bool = false) -> any URLSessionProtocol {
    let server = Audiobookshelf.shared.authentication.server
    return ClientCertificateSessionProvider.shared.session(
      for: server?.clientCertificate,
      allowedHosts: server?.certificateAllowedHosts ?? [],
      discretionary: discretionary
    )
  }

  static func download() -> any URLSessionProtocol {
    let server = Audiobookshelf.shared.authentication.server
    return ClientCertificateSessionProvider.shared.downloadSession(
      for: server?.clientCertificate,
      allowedHosts: server?.certificateAllowedHosts ?? []
    )
  }
}
