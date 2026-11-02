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
    guard !isImporting, let pendingImport else { return }

    isImporting = true
    let coordinator = coordinator
    let pending = pendingImport

    Task(priority: .userInitiated) { [weak self] in
      do {
        let reference = try coordinator.commit(pending, password: password)
        await MainActor.run {
          guard let self else {
            coordinator.remove(reference)
            return
          }
          self.pendingImport = nil
          self.reference = reference
          self.isAwaitingPassword = false
          self.isMissing = false
          self.errorMessage = nil
          self.onCertificateChanged?(reference)
        }
      } catch {
        await MainActor.run {
          guard let self else { return }
          self.errorMessage = error.localizedDescription
        }
      }
      await MainActor.run {
        self?.isImporting = false
      }
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
