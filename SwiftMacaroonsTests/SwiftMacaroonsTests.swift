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
        let key = "this is our super secret key; only we should know it".data(using: .utf8)!

        let mac = Macaroon(key: key, identifier: identifier, location: location)
        print(mac.signature)
        XCTAssert(mac.signature == "e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f")
    }

    func testFirstPartyCaveatChangeSignature() {
        var macaroon = getMacaroon()

        macaroon.addFirstPartyCaveat("test = caveat")
        XCTAssert(macaroon.signature == "197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67")
    }
    
    func testMacaroonWithNoCaviatsSerialization() {
        let macaroon = getMacaroon()
        let serialized = macaroon.serialize()
        XCTAssert(serialized == "MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAyZnNpZ25hdHVyZSDj2eApCFJsTAA5rhURQRXZf91ovyujebNCqvD2F9BVLwo")
    }
    
    func testMacaroonWithFirstPartyCaveatSerialization() {
        var macaroon = getMacaroon()
        macaroon.addFirstPartyCaveat("account = 3735928559")
        let serialized = macaroon.serialize()
        XCTAssert(serialized == "MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIB7-R2PykNvODB0IR3Nn4R9O7kVqZJM89mLXl3LbuCEoCg")
    }

    /*
    func testMacaroonWithThirdPartyCaveatSerialization() {
        var macaroon = getMacaroon()
        macaroon.addFirstPartyCaveat("account = 3735928559")
        macaroon.addThirdPartyCaveat("http://auth.mybank/", verificationId: "SECRET for 3rd party caveat", identifier: macaroon.identifier)
    XCTAssert(macaroon.serialize().hasPrefix("MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDFmY2lkIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDA1MXZpZC"))
    
    }
     */

    func testMacaroonDeserialization() {
        let serializedMacaroon = "MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAyZnNpZ25hdHVyZSDj2eApCFJsTAA5rhURQRXZf91ovyujebNCqvD2F9BVLwo"
        let mmacaroon = Macaroon.deserialize(serializedMacaroon)

        XCTAssert(mmacaroon != nil)
        let macaroon = mmacaroon!

        XCTAssert(macaroon.location == "http://mybank/")
		XCTAssert(macaroon.identifier == "we used our secret key")
		
		let macaroonRight = getMacaroon()
        XCTAssert(macaroon.signature == macaroonRight.signature)
    }

    func testMacaroonDeserializationV2() {
        let serializedMacaroon = "AgELc3RlYW1vai5uZXQCGmF1dGhvamktMS05NmFlMWY1MWFkNGU5ZWU1AAIPcXVlcnkgMTdkOCwxNzk4AAIRZXhwaXJlIDE1OTEyMTk0NzQAAAYgYa-aY8jkOqj6FEeFXmBrxB7YaRV7XL9tAoCwCxIl-u0"
        let mmacaroon = Macaroon.deserialize(serializedMacaroon)

        XCTAssert(mmacaroon != nil)
        let macaroon = mmacaroon!

        XCTAssert(macaroon.location == "steamoj.net")
        XCTAssert(macaroon.identifier == "authoji-1-96ae1f51ad4e9ee5")
        XCTAssert(macaroon.signature.count > 0)

    }
	
	func testMacaroonWithFirstPartyCaveatDeserialization() {
		let serializedMacaroon = "MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIB7-R2PykNvODB0IR3Nn4R9O7kVqZJM89mLXl3LbuCEoCg"
        let mmacaroon = Macaroon.deserialize(serializedMacaroon)

        XCTAssert(mmacaroon != nil)
        let macaroon = mmacaroon!

		var macaroonRight = getMacaroon()
        macaroonRight.addFirstPartyCaveat("account = 3735928559")
        
		XCTAssert(macaroon.caveats.first!.id == macaroonRight.caveats.first!.id)
	}

    /*
    
    func testMacaroonWithThirdPartyCaveatDeserialization() {
        let macaroonRight = getMacaroon()
        macaroonRight.addFirstPartyCaveat("account = 3735928559")
        macaroonRight.addThirdPartyCaveat("http://auth.mybank/", verificationId: "SECRET for 3rd party caveat", identifier: macaroonRight.identifier)
        
        let reverseMacaroon = Macaroon(bytes: macaroonRight.serialize())

        XCTAssert(reverseMacaroon.caveats.last!.verificationId! == macaroonRight.caveats.last!.verificationId!)
    }
    
    func testPrepareForRequest() {
        let originalMacaroon = Macaroon(bytes: "MDAyNGxvY2F0aW9uIGh0dHA6Ly9sb2NhbGhvc3Q6NDU2Ny8KMDAyY2lkZW50aWZpZXIgd2UgdXNlZCBvdXIgb3RoZXIgc2VjcmV0IGtleQowMDFkY2lkIGFjY291bnQgPSAzNzM1OTI4NTU5CjAwMmVjaWQga2VvZW9rZW9lZm9la29la29la2VvZWtvZWtvZWtmZXdqZXdvaQowMDUxdmlkIOH9qlSj6RvaRFw9rmbERtjPvfTj2drfcx9FHZikvjXI_Q9UwRgajUnqiCigNexFVGkZMGwmu7xN_3SpXfjPNl4wrGu5i7s_HQowMDIyY2wgaHR0cDovL2xvY2FsaG9zdDo0NTU1L2F1dGgKMDAyZnNpZ25hdHVyZSBTDwgtKErTSOdEdXAi18ASFQ2EseDInlSq2A81U2ShPwo")
        
        let dischargedMacaroon = Macaroon(bytes: "MDAyOGxvY2F0aW9uIGh0dHA6Ly9sb2NhbGhvc3QvNDU1NS9hdXRoCjAwMzVpZGVudGlmaWVyIGtlb2Vva2VvZWZvZWtvZWtvZWtlb2Vrb2Vrb2VrZmV3amV3b2kKMDAxM2NpZCB1c2VyPUFsaWNlCjAwMmZzaWduYXR1cmUg8uk47qyc0NLZ13G9J4Q63zS2wSPerQ7vhBdHKaQjlV8K")
        
        let finalMacaroon = originalMacaroon.prepareForRequest(dischargedMacaroon)
        
        XCTAssert(finalMacaroon.signature == "722a032c8b31a8fec9d3fc315e63d40e02d9462fad9db62c6e3afcbde35028c1")
    }
    
     */
    private func getMacaroon() -> Macaroon {
        let location = "http://mybank/"
        let identifier = "we used our secret key"
        let key = "this is our super secret key; only we should know it".data(using: .utf8)!
        
        return Macaroon(key: key, identifier: identifier, location: location)
    }
}
