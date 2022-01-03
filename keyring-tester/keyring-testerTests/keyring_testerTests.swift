//
//  keyring_testerTests.swift
//  keyring-testerTests
//
//  Created by Daniel Brotsky on 12/12/21.
//

import XCTest
@testable import keyring_tester

class keyring_testerTests: XCTestCase {

    func testRoundtrip() throws {
        let input: String = "testRoundtrip"
        XCTAssertNotNil(try? PasswordOps.setPassword(service: input, user: input, password: input))
        let result: String = try! PasswordOps.getPassword(service: input, user: input)
        XCTAssertEqual(input, result)
        XCTAssertNotNil(try? PasswordOps.deletePassword(service: input, user: input))
    }
    
    func testMissing() throws {
        XCTAssertNil(try? PasswordOps.getPassword(service: "testMissing", user: "testMissing"))
    }

}
