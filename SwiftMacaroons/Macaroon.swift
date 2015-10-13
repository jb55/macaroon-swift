import Foundation
import CryptoSwift

class Macaroon {
    
    var key: String
    var identifier: String
    var location: String
    
    var signature: String {
        get { return NSData.withBytes(signatureBytes).toHexString() }
    }
    
    var signatureBytes: [UInt8] = []
    var caveats: [Caveat]
    
    private let magicMacaroonKey = "macaroons-key-generator"
    
    init(key: String, identifier: String, location: String) {
        self.key = key
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
        let utf8Data = [UInt8](identifier.utf8)
        let authenticator = Authenticator.HMAC(key: derivedKey, variant: HMAC.Variant.sha256)
        return authenticator.authenticate(utf8Data)!
    }
    
//    func addFirstPartyCaveat(predicate: String) {
//        caveats.append(Caveat(id: predicate))
//        signature =
//        @signature = Utils.sign_first_party_caveat(@signature, predicate)
//    }
    
    func hmac(key key: String, data: String) -> [UInt8] {
        let utf8Key = [UInt8](key.utf8)
        let utf8Data = [UInt8](data.utf8)
        let authenticator = Authenticator.HMAC(key: utf8Key, variant: HMAC.Variant.sha256)
        let hmacUInt = authenticator.authenticate(utf8Data)!
        return hmacUInt
    }
}
