import API
import Foundation

final class ClientCertificateViewModel: ClientCertificateView.Model {
  private let coordinator: ClientCertificateImportCoordinator
  private var pendingImport: PendingClientCertificateImport?

  init(
    reference: ClientCertificateReference?,
    coordinator: ClientCertificateImportCoordinator = ClientCertificateImportCoordinator()
  ) {
    self.coordinator = coordinator
    super.init(reference: reference)
  }

  override func importFile(at url: URL) {
    let didAccess = url.startAccessingSecurityScopedResource()
    defer {
      if didAccess {
        url.stopAccessingSecurityScopedResource()
      }
    }

    do {
      let data = try Data(contentsOf: url)
      let displayName = url.deletingPathExtension().lastPathComponent
      pendingImport = coordinator.prepare(data: data, displayName: displayName)
      isAwaitingPassword = true
      errorMessage = nil
    } catch {
      errorMessage = error.localizedDescription
    }
  }

  override func submitPassword(_ password: String) {
    guard let pendingImport else { return }

    isImporting = true
    defer { isImporting = false }

    do {
      let reference = try coordinator.commit(pendingImport, password: password)
      self.pendingImport = nil
      self.reference = reference
      isAwaitingPassword = false
      isMissing = false
      errorMessage = nil
      onCertificateChanged?(reference)
    } catch {
      errorMessage = error.localizedDescription
    }
  }

  override func removeCertificate() {
    coordinator.remove(reference)
    reference = nil
    isMissing = false
    errorMessage = nil
    onCertificateChanged?(nil)
  }
}
