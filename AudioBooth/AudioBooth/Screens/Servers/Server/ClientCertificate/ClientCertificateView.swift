import API
import Combine
import SwiftUI
import UniformTypeIdentifiers

struct ClientCertificateView: View {
  @Environment(\.appTheme) var theme

  @ObservedObject var model: Model

  @State private var isShowingFileImporter = false
  @State private var isShowingRemoveConfirmation = false
  @State private var password = ""

  var body: some View {
    Form {
      Section {
        HStack {
          Text("Status")
          Spacer()
          Text(model.isMissing ? "Certificate missing" : (model.reference?.displayName ?? "Not configured"))
            .foregroundColor(model.isMissing ? .red : .secondary)
        }

        if model.isMissing {
          Text("The stored certificate is missing. Import the certificate again.")
            .font(.caption)
            .foregroundColor(.secondary)
        }

        if let reference = model.reference {
          HStack {
            Text("Fingerprint")
            Spacer()
            Text(formattedFingerprint(reference.fingerprintSHA256))
              .font(.caption.monospaced())
              .foregroundColor(.secondary)
              .multilineTextAlignment(.trailing)
              .textSelection(.enabled)
          }

          HStack {
            Text("Imported")
            Spacer()
            Text(reference.importedAt.formatted(date: .abbreviated, time: .shortened))
              .foregroundColor(.secondary)
          }
        }
      } footer: {
        Text("OIDC sign-in uses the system browser. A system certificate profile is also required.")
          .font(.caption)
      }
      .listRowBackground(theme.colors.background.card)

      Section {
        Button {
          password = ""
          isShowingFileImporter = true
        } label: {
          HStack {
            Image(systemName: "square.and.arrow.down")
            Text(model.reference == nil ? "Import Certificate" : "Replace Certificate")
          }
        }

        if model.reference != nil {
          Button(role: .destructive) {
            isShowingRemoveConfirmation = true
          } label: {
            HStack {
              Image(systemName: "trash")
              Text("Remove Certificate")
            }
          }
          .confirmationDialog(
            "Remove Certificate",
            isPresented: $isShowingRemoveConfirmation,
            titleVisibility: .visible
          ) {
            Button("Remove Certificate", role: .destructive) {
              model.removeCertificate()
            }
            Button("Cancel", role: .cancel) {}
          } message: {
            Text("The certificate will be deleted from this device.")
          }
        }
      }
      .listRowBackground(theme.colors.background.card)
    }
    .scrollContentBackground(.hidden)
    .background(theme.colors.background.page.ignoresSafeArea())
    .navigationTitle("Client Certificate")
    .navigationBarTitleDisplayMode(.inline)
    .fileImporter(
      isPresented: $isShowingFileImporter,
      allowedContentTypes: [
        UTType(filenameExtension: "p12"),
        UTType(filenameExtension: "pfx"),
        .data,
      ].compactMap { $0 },
      allowsMultipleSelection: false
    ) { result in
      switch result {
      case .success(let urls):
        guard let url = urls.first else { return }
        model.importFile(at: url)
      case .failure(let error):
        model.errorMessage = error.localizedDescription
      }
    }
    .sheet(isPresented: $model.isAwaitingPassword) {
      NavigationStack {
        Form {
          Section {
            SecureField("Password", text: $password)
              .textContentType(.password)
          } header: {
            Text("Certificate Password")
          } footer: {
            Text("Enter the password for the PKCS#12 file.")
              .font(.caption)
          }
          .listRowBackground(theme.colors.background.card)
        }
        .scrollContentBackground(.hidden)
        .background(theme.colors.background.page.ignoresSafeArea())
        .navigationTitle("Import Certificate")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
          ToolbarItem(placement: .cancellationAction) {
            Button("Cancel") {
              password = ""
              model.isAwaitingPassword = false
            }
            .tint(.primary)
          }
          ToolbarItem(placement: .confirmationAction) {
            Button("Import") {
              model.submitPassword(password)
              password = ""
            }
            .disabled(password.isEmpty || model.isImporting)
            .tint(.primary)
          }
        }
      }
    }
    .onAppear {
      model.refreshStoredCertificateState()
    }
    .onChange(of: model.errorMessage) { _, errorMessage in
      guard let errorMessage else { return }
      Toast(error: errorMessage).show()
      model.errorMessage = nil
    }
  }

  private func formattedFingerprint(_ fingerprint: String) -> String {
    let characters = Array(
      fingerprint
        .replacingOccurrences(of: ":", with: "")
        .uppercased()
    )

    return stride(from: 0, to: characters.count, by: 2)
      .map { String(characters[$0..<min($0 + 2, characters.count)]) }
      .joined(separator: ":")
  }
}

extension ClientCertificateView {
  @Observable
  class Model: ObservableObject {
    var reference: ClientCertificateReference?
    var isImporting = false
    var isAwaitingPassword = false
    var isMissing = false
    var errorMessage: String?
    var onCertificateChanged: ((ClientCertificateReference?) -> Void)?

    init(reference: ClientCertificateReference? = nil) {
      self.reference = reference
    }

    func refreshStoredCertificateState() {
      guard let reference else {
        isMissing = false
        return
      }
      isMissing = ClientCertificateStore.shared.load(id: reference.id) == nil
    }

    func importFile(at url: URL) {}
    func submitPassword(_ password: String) {}
    func removeCertificate() {}
  }
}
