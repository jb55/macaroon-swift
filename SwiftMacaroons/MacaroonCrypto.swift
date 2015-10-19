import Foundation

class MacaroonCrypto {
    private static let magicMacaroonKey = "macaroons-key-generator".toInt8()
    
    static func createVerificationId(verificationId: [UInt8], signature: [UInt8]) -> [UInt8] {
        let caveatKey = generateDerivedKey(verificationId)
        let derivedCaveatKey = caveatKey.trunc(32)
        let truncatedSignature = signature.trunc(32)
        return Crypto.secretBox(derivedCaveatKey, secretKey: truncatedSignature)
    }
    
    static func signWithThirdPartyCaveat(verification: [UInt8], caveatId: [UInt8], signature: [UInt8]) -> [UInt8] {
        var verificationIdHash = Crypto.hmac(key: signature, data: verification)
        let caveatIdHash = Crypto.hmac(key: signature, data: caveatId)
        verificationIdHash.appendContentsOf(caveatIdHash)
        
        return Crypto.hmac(key: signature, data: verificationIdHash)
    }
    
    static func initialSignature(key: [UInt8], identifier: [UInt8]) -> [UInt8] {
        let derivedKey = generateDerivedKey(key)
        return Crypto.hmac(key: derivedKey, data: identifier)
    }
    
    static func generateDerivedKey(key: [UInt8]) -> [UInt8] {
        return Crypto.hmac(key: magicMacaroonKey, data: key)
    }
    
    static func bindSignature(signature: [UInt8], with anotherSignature: [UInt8]) -> [UInt8] {
        let emptyArray = [UInt8].init(count: 32, repeatedValue: 0x00)
        
        var hash1 = Crypto.hmac(key: emptyArray, data: signature)
        let hash2 = Crypto.hmac(key: emptyArray, data: anotherSignature)
        hash1.appendContentsOf(hash2)
        
        return Crypto.hmac(key: emptyArray, data: hash1)
    }
    
}