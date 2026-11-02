import XCTest
@testable import API

final class ClientCertificateAssetTests: XCTestCase {
  private let data = Data(0..<256)

  func testTwoHundredBoundedRangeIsSliced() {
    let plan = ClientCertificateResourceLoader.plan(
      data: data, statusCode: 200,
      requestedOffset: 100, requestedLength: 60, requestsAllDataToEnd: false
    )
    XCTAssertEqual(plan.bytes, data[100..<160])
    XCTAssertEqual(plan.totalLength, 256)
    XCTAssertFalse(plan.isRangeResponse)
  }

  func testTwoHundredPrefixIsSliced() {
    let plan = ClientCertificateResourceLoader.plan(
      data: data, statusCode: 200,
      requestedOffset: 0, requestedLength: 60, requestsAllDataToEnd: false
    )
    XCTAssertEqual(plan.bytes, data[0..<60])
    XCTAssertEqual(plan.totalLength, 256)
  }

  func testTwoHundredOpenRangeIsSlicedToEnd() {
    let plan = ClientCertificateResourceLoader.plan(
      data: data, statusCode: 200,
      requestedOffset: 100, requestedLength: 0, requestsAllDataToEnd: true
    )
    XCTAssertEqual(plan.bytes, data[100..<256])
    XCTAssertEqual(plan.bytes.count, 156)
  }

  func testTwoSixReturnsRangeDataUnchanged() {
    let plan = ClientCertificateResourceLoader.plan(
      data: data, statusCode: 206,
      requestedOffset: 100, requestedLength: 60, requestsAllDataToEnd: false
    )
    XCTAssertEqual(plan.bytes, data)
  }

  func testTwoHundredOffsetBeyondEndYieldsEmptyData() {
    let plan = ClientCertificateResourceLoader.plan(
      data: data, statusCode: 200,
      requestedOffset: 1000, requestedLength: 0, requestsAllDataToEnd: true
    )
    XCTAssertEqual(plan.bytes, Data())
    XCTAssertEqual(plan.totalLength, 256)
  }

  func testLengthLargerThanResourceIsClamped() {
    let plan = ClientCertificateResourceLoader.plan(
      data: data, statusCode: 200,
      requestedOffset: 200, requestedLength: 1000, requestsAllDataToEnd: false
    )
    XCTAssertEqual(plan.bytes, data[200..<256])
  }
}
