import Foundation
import Nuke

extension ImagePipeline {
  nonisolated private static let dataCache = try? DataCache(name: "me.jgrenier.audioBS.images")

  nonisolated static func audioBooth(
    customHeaders: [String: String]?,
    clientCertificate: ClientCertificateReference? = nil,
    allowedHosts: Set<String> = []
  ) -> ImagePipeline {
    ImagePipeline {
      let configuration = DataLoader.defaultConfiguration
      configuration.urlCache = nil
      configuration.httpAdditionalHeaders = customHeaders
      let loader = DataLoader(configuration: configuration)
      if let clientCertificate {
        loader.delegate = ClientCertificateChallengeHandler(
          certificateID: clientCertificate.id,
          allowedHosts: allowedHosts
        )
      }
      $0.dataLoader = loader
      $0.dataCache = dataCache
    }
  }
}
