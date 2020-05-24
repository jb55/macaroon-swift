import Foundation

class MacaroonCrypto {
    private static let magicMacaroonKey = "macaroons-key-generator".toInt8().data
    
    //static func createVerificationId(verificationId: Data, signature: Data) -> Data {
    //    let caveatKey = generateDerivedKey(key: verificationId)
    //    let derivedCaveatKey = caveatKey.bytes.trunc(length: 32).data
    //    let truncatedSignature = signature.bytes.trunc(length: 32).data
    //    return Crypto.secretBox(message: derivedCaveatKey, secretKey: truncatedSignature)
    //}
    
    static func signWithThirdPartyCaveat(verification: Data, caveatId: Data, signature: Data) -> Data {
        var verificationIdHash = HMAC.hmac(key: signature, data: verification)
        let caveatIdHash = HMAC.hmac(key: signature, data: caveatId)
        verificationIdHash.append(contentsOf: caveatIdHash)

        return HMAC.hmac(key: signature, data: verificationIdHash)
    }
    
    static func initialSignature(key: Data, identifier: Data) -> Data {
        let derivedKey = generateDerivedKey(key: key)
        return HMAC.hmac(key: derivedKey, data: identifier)
    }
    
    static func generateDerivedKey(key: Data) -> Data {
        return HMAC.hmac(key: magicMacaroonKey, data: key)
    }
    
    static func bindSignature(signature: Data, with anotherSignature: Data) -> Data {
        let emptyArray = [UInt8].init(repeating: 0x00, count: 32)
        
        var hash1 = HMAC.hmac(key: emptyArray.data, data: signature)
        let hash2 = HMAC.hmac(key: emptyArray.data, data: anotherSignature)
        hash1.append(contentsOf: hash2)
        
        return HMAC.hmac(key: emptyArray.data, data: hash1)
    }
    
}
