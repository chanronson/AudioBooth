import Foundation

final class ClientCertificateChallengeHandler: NSObject, URLSessionTaskDelegate {
  private let certificateID: String
  private let allowedHosts: Set<String>
  private let store: any ClientCertificateStoring

  init(
    certificateID: String,
    allowedHosts: Set<String>,
    store: any ClientCertificateStoring = ClientCertificateStore.shared
  ) {
    self.certificateID = certificateID
    self.allowedHosts = allowedHosts
    self.store = store
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping @Sendable (
      URLSession.AuthChallengeDisposition,
      URLCredential?
    ) -> Void
  ) {
    guard challenge.protectionSpace.authenticationMethod
      == NSURLAuthenticationMethodClientCertificate
    else {
      completionHandler(.performDefaultHandling, nil)
      return
    }

    let port = challenge.protectionSpace.port > 0
      ? challenge.protectionSpace.port
      : 443

    guard
      Self.isAllowed(
        host: challenge.protectionSpace.host,
        port: port,
        allowedHosts: allowedHosts
      ),
      let stored = store.load(id: certificateID),
      let credential = ClientCertificateCredentialProvider.credential(
        for: stored.reference,
        store: store
      )
    else {
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }

    completionHandler(.useCredential, credential)
  }

  static func isAllowed(
    host: String,
    port: Int,
    allowedHosts: Set<String>
  ) -> Bool {
    guard
      let endpoint = ClientCertificateEndpoint(host: host, port: port)
    else {
      return false
    }
    return allowedHosts.contains(endpoint.key)
  }
}

public enum ClientCertificateChallengeDelegate {
  public static func make(
    for reference: ClientCertificateReference,
    allowedHosts: Set<String>
  ) -> URLSessionDelegate {
    ClientCertificateChallengeHandler(
      certificateID: reference.id,
      allowedHosts: allowedHosts
    )
  }
}
