import XCTest
@testable import API

final class ClientCertificateImporterTests: XCTestCase {
  private func fixture(_ name: String) throws -> Data {
    let url = try XCTUnwrap(
      Bundle.module.url(
        forResource: name,
        withExtension: "p12",
        subdirectory: "Fixtures"
      )
    )
    return try Data(contentsOf: url)
  }

  func testImportsValidPKCS12() throws {
    let stored = try ClientCertificateImporter.importPKCS12(
      data: fixture("client"),
      password: "test",
      displayName: "client"
    )

    XCTAssertEqual(stored.reference.displayName, "client")
    XCTAssertEqual(stored.reference.fingerprintSHA256.count, 64)
    XCTAssertEqual(
      stored.reference.fingerprintSHA256,
      stored.reference.fingerprintSHA256.lowercased()
    )
    XCTAssertEqual(stored.p12Data, try fixture("client"))
  }

  func testUsesCertificateCommonNameWhenDisplayNameIsEmpty() throws {
    let stored = try ClientCertificateImporter.importPKCS12(
      data: fixture("client"),
      password: "test",
      displayName: ""
    )

    XCTAssertEqual(stored.reference.displayName, "AudioBooth Test Client")
  }

  func testRejectsWrongPassword() throws {
    XCTAssertThrowsError(
      try ClientCertificateImporter.importPKCS12(
        data: fixture("client"),
        password: "wrong",
        displayName: "client"
      )
    ) { error in
      XCTAssertEqual(error as? ClientCertificateImportError, .wrongPassword)
    }
  }

  func testRejectsInvalidData() {
    XCTAssertThrowsError(
      try ClientCertificateImporter.importPKCS12(
        data: Data("not a p12".utf8),
        password: "test",
        displayName: "client"
      )
    ) { error in
      XCTAssertEqual(error as? ClientCertificateImportError, .invalidFormat)
    }
  }

  func testRejectsOversizedData() {
    let data = Data(count: ClientCertificateImporter.maximumFileSize + 1)

    XCTAssertThrowsError(
      try ClientCertificateImporter.importPKCS12(
        data: data,
        password: "test",
        displayName: "client"
      )
    ) { error in
      XCTAssertEqual(error as? ClientCertificateImportError, .tooLarge)
    }
  }

  func testRejectsPKCS12WithoutIdentity() throws {
    XCTAssertThrowsError(
      try ClientCertificateImporter.importPKCS12(
        data: fixture("client-cert-only"),
        password: "test",
        displayName: "client"
      )
    ) { error in
      XCTAssertEqual(error as? ClientCertificateImportError, .missingIdentity)
    }
  }
}
