//
//  SwiftMacaroonsTests.swift
//  SwiftMacaroonsTests
//
//  Created by Ygor Bruxel on 10/11/15.
//  Copyright © 2015 Bearch Inc. All rights reserved.
//

import XCTest
@testable import SwiftMacaroons

class SwiftMacaroonsTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testSignatureWithoutCaveats() {
        let location = "http://mybank/"
        let identifier = "we used our secret key"
        let key = "this is our super secret key; only we should know it"

        let mac = Macaroon(key: key, identifier: identifier, location: location)
        XCTAssert(mac.signature == "e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f")
    }

    func testFirstPartyCaveatChangeSignature() {
        let macaroon = getMacaroon()
        
        macaroon.addFirstPartyCaveat("test = caveat")
        XCTAssert(macaroon.signature == "197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67")
    }
    
    func testMacaroonWithNoCaviatsSerialization() {
        let macaroon = getMacaroon()
        XCTAssert(macaroon.serialize() == "MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAyZnNpZ25hdHVyZSDj2eApCFJsTAA5rhURQRXZf91ovyujebNCqvD2F9BVLwo")
    }
    
    func testMacaroonWithFirstPartyCaveatSerialization() {
        let macaroon = getMacaroon()
        macaroon.addFirstPartyCaveat("account = 3735928559")
        XCTAssert(macaroon.serialize() == "MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIB7-R2PykNvODB0IR3Nn4R9O7kVqZJM89mLXl3LbuCEoCg")
    }
    
    func testMacaroonWithThirdPartyCaveatSerialization() {
        let macaroon = getMacaroon()
        macaroon.addFirstPartyCaveat("account = 3735928559")
        macaroon.addThirdPartyCaveat("http://auth.mybank/", verificationId: "SECRET for 3rd party caveat", identifier: macaroon.identifier)
		XCTAssert(macaroon.serialize().hasPrefix("MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDFmY2lkIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDA1MXZpZC"))
    }
    
    func testMacaroonDeserialization() {
        let serializedMacaroon = "MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAyZnNpZ25hdHVyZSDj2eApCFJsTAA5rhURQRXZf91ovyujebNCqvD2F9BVLwo"
        XCTAssert(Macaroon(bytes: serializedMacaroon).location == "http://mybank/")

    }
    
    private func getMacaroon() -> Macaroon {
        let location = "http://mybank/"
        let identifier = "we used our secret key"
        let key = "this is our super secret key; only we should know it"
        
        return Macaroon(key: key, identifier: identifier, location: location)
    }
}
