import Foundation
import CryptoSwift

class Macaroon {
    
    var key: String
    var identifier: String
    var location: String
    var signature: String
    var caveats: [Caveat]
    
    private let magicMacaroonKey = "macaroons-key-generator"
    
    init(key: String, identifier: String, location: String) {
        self.key = key
        self.identifier = identifier
        self.location = location
        self.signature = ""
        self.caveats = []
        self.createSignature()
    }
    
    func generateDerivedKey() -> [UInt8] {
        let utf8Key = [UInt8](magicMacaroonKey.utf8)
        let utf8Data = [UInt8](key.utf8)
        let authenticator = Authenticator.HMAC(key: utf8Key, variant: HMAC.Variant.sha256)
        return authenticator.authenticate(utf8Data)!

    }
    
    func createSignature() {
        let derivedKey = generateDerivedKey()
        
        let utf8Key = derivedKey
        let utf8Data = [UInt8](identifier.utf8)
        
        let authenticator = Authenticator.HMAC(key: utf8Key, variant: HMAC.Variant.sha256)
        let a = authenticator.authenticate(utf8Data)!
        self.signature = NSData.withBytes(a).toHexString()
        
//        self.signature = self.hmac(key: [UInt8](derivedKey), data: identifier)
    }
    
//    func addFirstPartyCaveat(predicate: String) {
//        caveats.append(Caveat(id: predicate))
//        signature =
//        @signature = Utils.sign_first_party_caveat(@signature, predicate)
//    }
    
    func hmac(key key: String, data: String) -> String {
        let utf8Key = [UInt8](key.utf8)
        let utf8Data = [UInt8](data.utf8)
        let authenticator = Authenticator.HMAC(key: utf8Key, variant: HMAC.Variant.sha256)
        let hmacUInt = authenticator.authenticate(utf8Data)!
        return NSData.withBytes(hmacUInt).toHexString()
    }
}
