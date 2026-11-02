#if !os(watchOS)
import AVFoundation
import Foundation
import Pulse

public final class ClientCertificateAsset: AVURLAsset {
  public let originalURL: URL

  private let resourceLoaderDelegate: ClientCertificateResourceLoader

  public init(
    url: URL,
    headers: [String: String],
    reference: ClientCertificateReference,
    allowedHosts: Set<String>
  ) {
    self.originalURL = url

    let loader = ClientCertificateResourceLoader(
      reference: reference,
      allowedHosts: allowedHosts,
      headers: headers
    )
    self.resourceLoaderDelegate = loader

    super.init(url: Self.customURL(for: url), options: nil)
    resourceLoader.setDelegate(loader, queue: .global(qos: .userInitiated))
  }

  private static func customURL(for url: URL) -> URL {
    guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
      return url
    }
    components.scheme = "audiobooth-mtls"
    return components.url ?? url
  }
}

final class ClientCertificateResourceLoader: NSObject, AVAssetResourceLoaderDelegate, @unchecked Sendable {
  private let session: any URLSessionProtocol
  private let headers: [String: String]
  private let lock = NSLock()
  private var tasks: [ObjectIdentifier: URLSessionDataTask] = [:]

  init(
    reference: ClientCertificateReference,
    allowedHosts: Set<String>,
    headers: [String: String]
  ) {
    self.session = ClientCertificateSessionProvider.shared.downloadSession(
      for: reference,
      allowedHosts: allowedHosts
    )
    self.headers = headers
  }

  func resourceLoader(
    _ resourceLoader: AVAssetResourceLoader,
    shouldWaitForLoadingOfRequestedResource loadingRequest: AVAssetResourceLoadingRequest
  ) -> Bool {
    do {
      let request = try makeRequest(for: loadingRequest)
      start(request, for: loadingRequest)
      return true
    } catch {
      loadingRequest.finishLoading(with: error)
      return true
    }
  }

  func resourceLoader(
    _ resourceLoader: AVAssetResourceLoader,
    didCancel loadingRequest: AVAssetResourceLoadingRequest
  ) {
    lock.lock()
    let task = tasks.removeValue(forKey: ObjectIdentifier(loadingRequest))
    lock.unlock()

    task?.cancel()
  }

  private func start(_ request: URLRequest, for loadingRequest: AVAssetResourceLoadingRequest) {
    let key = ObjectIdentifier(loadingRequest)
    let box = LoadingRequestBox(loadingRequest)

    let task = session.dataTask(with: request) { [weak self] data, response, error in
      guard let self else { return }

      self.lock.lock()
      let isTracked = self.tasks.removeValue(forKey: key) != nil
      self.lock.unlock()

      guard isTracked else { return }

      if let error {
        box.request.finishLoading(with: error)
        return
      }

      guard let httpResponse = response as? HTTPURLResponse,
        200...299 ~= httpResponse.statusCode
      else {
        box.request.finishLoading(with: URLError(.badServerResponse))
        return
      }

      let isRangeResponse = httpResponse.statusCode == 206

      if let information = box.request.contentInformationRequest {
        information.contentType = httpResponse.mimeType
        if isRangeResponse,
          let contentRange = httpResponse.value(forHTTPHeaderField: "Content-Range"),
          let totalLength = Self.totalLength(from: contentRange)
        {
          information.contentLength = totalLength
          information.isByteRangeAccessSupported = true
        } else {
          information.contentLength = httpResponse.expectedContentLength
          information.isByteRangeAccessSupported = isRangeResponse
        }
      }

      if let dataRequest = box.request.dataRequest {
        let plan = Self.plan(
          data: data ?? Data(),
          statusCode: httpResponse.statusCode,
          requestedOffset: dataRequest.requestedOffset,
          requestedLength: dataRequest.requestedLength,
          requestsAllDataToEnd: dataRequest.requestsAllDataToEndOfResource
        )
        dataRequest.respond(with: plan.bytes)
      }

      box.request.finishLoading()
    }

    lock.lock()
    tasks[key] = task
    lock.unlock()

    task.resume()
  }

  private func makeRequest(for loadingRequest: AVAssetResourceLoadingRequest) throws -> URLRequest {
    guard let url = loadingRequest.request.url,
      var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
    else {
      throw URLError(.badURL)
    }

    components.scheme = "https"

    guard let requestURL = components.url else {
      throw URLError(.badURL)
    }

    var request = URLRequest(url: requestURL)
    for (key, value) in headers {
      request.setValue(value, forHTTPHeaderField: key)
    }

    if let dataRequest = loadingRequest.dataRequest {
      let start = dataRequest.requestedOffset
      if dataRequest.requestsAllDataToEndOfResource || dataRequest.requestedLength <= 0 {
        request.setValue("bytes=\(start)-", forHTTPHeaderField: "Range")
      } else {
        let end = start + Int64(dataRequest.requestedLength) - 1
        request.setValue("bytes=\(start)-\(end)", forHTTPHeaderField: "Range")
      }
    } else if loadingRequest.contentInformationRequest != nil {
      request.setValue("bytes=0-0", forHTTPHeaderField: "Range")
    }

    return request
  }

  static func plan(
    data: Data,
    statusCode: Int,
    requestedOffset: Int64,
    requestedLength: Int,
    requestsAllDataToEnd: Bool
  ) -> (bytes: Data, totalLength: Int, isRangeResponse: Bool) {
    let isRangeResponse = statusCode == 206

    if isRangeResponse || (requestedOffset <= 0 && requestedLength <= 0 && !requestsAllDataToEnd) {
      return (data, data.count, isRangeResponse)
    }

    let start = min(max(0, requestedOffset), Int64(data.count))
    let available = Int64(data.count) - start
    let requested = requestsAllDataToEnd || requestedLength <= 0
      ? available
      : min(Int64(requestedLength), available)

    let bytes = data.dropFirst(Int(start)).prefix(Int(requested))
    return (bytes, data.count, isRangeResponse)
  }

  private static func totalLength(from contentRange: String) -> Int64? {
    guard let separator = contentRange.lastIndex(of: "/") else { return nil }
    let value = contentRange[contentRange.index(after: separator)...]
      .trimmingCharacters(in: .whitespaces)
    return Int64(value)
  }
}

private final class LoadingRequestBox: @unchecked Sendable {
  let request: AVAssetResourceLoadingRequest

  init(_ request: AVAssetResourceLoadingRequest) {
    self.request = request
  }
}
#endif
