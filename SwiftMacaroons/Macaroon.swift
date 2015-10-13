import Foundation
import CryptoSwift

class Macaroon {
    
    var key: [UInt8]
    var identifier: String
    var location: String
    
    var signature: String {
        get { return NSData.withBytes(signatureBytes).toHexString() }
    }
    
    var signatureBytes: [UInt8] = []
    var caveats: [Caveat]
    
    private let magicMacaroonKey = [UInt8]("macaroons-key-generator".utf8)
    
    init(key: String, identifier: String, location: String) {
        self.key = [UInt8](key.utf8)
        self.identifier = identifier
        self.location = location
        self.caveats = []
        self.signatureBytes = self.createSignature()
    }
    
    func generateDerivedKey() -> [UInt8] {
        return hmac(key: magicMacaroonKey, data: key)
    }
    
    func createSignature() -> [UInt8] {
        let derivedKey = generateDerivedKey()
        return hmac(key: derivedKey, data: stringToIntArray(identifier))
    }
    
    func addFirstPartyCaveat(predicate: String) {
        caveats.append(Caveat(id: predicate))
        signatureBytes = hmac(key: signatureBytes, data: stringToIntArray(predicate))
    }
    
    func stringToIntArray(string: String) -> [UInt8] {
        return [UInt8](string.utf8)
    }
    
    func hmac(key key: [UInt8], data: [UInt8]) -> [UInt8] {
        let authenticator = Authenticator.HMAC(key: key, variant: HMAC.Variant.sha256)
        let hmacUInt = authenticator.authenticate(data)!
        return hmacUInt
    }
}
