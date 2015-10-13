import Foundation
import CryptoSwift
import SwiftyBase64

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
    private let packetPrefixLength = 4
    
    init(key: String, identifier: String, location: String) {
        self.key = [UInt8](key.utf8)
        self.identifier = identifier
        self.location = location
        self.caveats = []
        self.signatureBytes = self.createSignature()
    }
    
    func addFirstPartyCaveat(predicate: String) {
        caveats.append(Caveat(id: predicate))
        signatureBytes = hmac(key: signatureBytes, data: stringToIntArray(predicate))
    }
    
    func serialize() -> String {
        var packets = [UInt8]()
        packets.appendContentsOf(packetize("location", data: [UInt8](location.utf8)))
        packets.appendContentsOf(packetize("identifier", data: [UInt8](identifier.utf8)))
        packets.appendContentsOf(packetize("signature", data: signatureBytes))
        return SwiftyBase64.EncodeString(packets, alphabet:.URLAndFilenameSafe).stringByReplacingOccurrencesOfString("=", withString: "")
    }
    
    func packetize(key: String, data: [UInt8]) -> [UInt8] {
        let packet_size = packetPrefixLength + 2 + key.characters.count + data.count
        var header = String(packet_size, radix: 16)
        
        if header.characters.count < 4 {
            header = "0".stringByAppendingString(header)
        }
        if header.characters.count < 4 {
            header = "0".stringByAppendingString(header)
        }
        if header.characters.count < 4 {
            header = "0".stringByAppendingString(header)
        }
        
        var content = [UInt8]("\(key) ".utf8)
        content.appendContentsOf(data)
        content.appendContentsOf([UInt8]("\n".utf8))
        
        var result = [UInt8](header.utf8)
        result.appendContentsOf(content)
        return result
    }
    
    private func createSignature() -> [UInt8] {
        let derivedKey = generateDerivedKey()
        return hmac(key: derivedKey, data: stringToIntArray(identifier))
    }
    
    private func generateDerivedKey() -> [UInt8] {
        return hmac(key: magicMacaroonKey, data: key)
    }
    
    private func stringToIntArray(string: String) -> [UInt8] {
        return [UInt8](string.utf8)
    }
    
    private func hmac(key key: [UInt8], data: [UInt8]) -> [UInt8] {
        let authenticator = Authenticator.HMAC(key: key, variant: HMAC.Variant.sha256)
        let hmacUInt = authenticator.authenticate(data)!
        return hmacUInt
    }
}
