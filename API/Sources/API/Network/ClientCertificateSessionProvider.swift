import Foundation
import Pulse

public final class ClientCertificateSessionProvider: @unchecked Sendable {
  public static let shared = ClientCertificateSessionProvider()

  private let lock = NSLock()
  private var sessions: [String: any URLSessionProtocol] = [:]

  public init() {}

  public func session(
    for reference: ClientCertificateReference?,
    allowedHosts: Set<String>,
    discretionary: Bool
  ) -> any URLSessionProtocol {
    guard let reference else {
      return discretionary ? Self.discretionarySession : Self.session
    }

    let key = Self.cacheKey(
      certificateID: reference.id,
      allowedHosts: allowedHosts,
      discretionary: discretionary
    )

    lock.lock()
    defer { lock.unlock() }

    if let cached = sessions[key] {
      return cached
    }

    let handler = ClientCertificateChallengeHandler(
      certificateID: reference.id,
      allowedHosts: allowedHosts
    )
    let session = Self.makeSession(
      delegate: handler,
      discretionary: discretionary
    )
    sessions[key] = session
    return session
  }

  public func invalidate(certificateID: String) {
    let prefix = "\(certificateID)|"
    lock.lock()
    defer { lock.unlock() }
    sessions = sessions.filter { !$0.key.hasPrefix(prefix) }
  }

  private static func cacheKey(
    certificateID: String,
    allowedHosts: Set<String>,
    discretionary: Bool
  ) -> String {
    let hosts = allowedHosts.sorted().joined(separator: ",")
    return "\(certificateID)|\(hosts)|\(discretionary)"
  }

  private static func makeSession(
    delegate: URLSessionDelegate,
    discretionary: Bool
  ) -> any URLSessionProtocol {
    let config = configuration(discretionary: discretionary)

    #if os(watchOS)
    return URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
    #else
    return URLSessionProxy(configuration: config, delegate: delegate, delegateQueue: nil)
    #endif
  }

  private static func configuration(discretionary: Bool) -> URLSessionConfiguration {
    let config = URLSessionConfiguration.default
    config.timeoutIntervalForRequest = 30
    config.timeoutIntervalForResource = discretionary ? 60 : 120

    config.httpAdditionalHeaders = ["User-Agent": userAgent]

    #if os(watchOS)
    config.timeoutIntervalForResource = 300
    config.allowsExpensiveNetworkAccess = true
    config.allowsConstrainedNetworkAccess = true
    config.allowsCellularAccess = true
    if discretionary {
      config.waitsForConnectivity = true
    }
    #endif

    if discretionary {
      #if os(iOS)
      config.sessionSendsLaunchEvents = true
      config.isDiscretionary = true
      config.shouldUseExtendedBackgroundIdleMode = true
      #endif
    }

    return config
  }

  private static let session: URLSessionProtocol = {
    let config = configuration(discretionary: false)

    #if os(watchOS)
    return URLSession(configuration: config)
    #else
    return URLSessionProxy(configuration: config)
    #endif
  }()

  private static let discretionarySession: URLSessionProtocol = {
    let config = configuration(discretionary: true)

    #if os(watchOS)
    return URLSession(configuration: config)
    #else
    return URLSessionProxy(configuration: config)
    #endif
  }()

  private static let userAgent: String = {
    let os = ProcessInfo.processInfo.operatingSystemVersion
    let osVersion = "\(os.majorVersion)_\(os.minorVersion)_\(os.patchVersion)"

    #if targetEnvironment(macCatalyst)
    let platform = "Macintosh; Mac OS X \(osVersion)"
    #elseif os(watchOS)
    let platform = "Apple Watch; watchOS/\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
    #else
    let platform =
      Device.identifier.hasPrefix("iPad")
      ? "iPad; CPU OS \(osVersion) like Mac OS X"
      : "iPhone; CPU iPhone OS \(osVersion) like Mac OS X"
    #endif

    let appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"

    return "AudioBooth/\(appVersion) (\(platform))"
  }()
}
