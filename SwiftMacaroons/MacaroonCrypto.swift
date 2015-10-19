import Foundation

class MacaroonCrypto {
    private static let magicMacaroonKey = "macaroons-key-generator".toInt8()
    
    static func createVerificationId(verificationId: [UInt8], signature: [UInt8]) -> [UInt8] {
        let caveatKey = MacaroonCrypto.generateDerivedKey(verificationId)
        
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
    
    static func generateDerivedKey(key: [UInt8]) -> [UInt8] {
        return Crypto.hmac(key: magicMacaroonKey, data: key)
    }
}