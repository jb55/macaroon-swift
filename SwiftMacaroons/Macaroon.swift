import Foundation
import CryptoSwift
import SwiftyBase64
import Sodium

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

    func addThirdPartyCaveat(location: String, verificationId: String, identifier: String) {
        let caveatKey = hmac(key: magicMacaroonKey, data: [UInt8](verificationId.utf8))
        
        let derivedCaveatKey = truncInt8ToNSData(caveatKey)
        let truncatedSignature = truncInt8ToNSData(signatureBytes)
        let verification:NSData = Sodium()!.secretBox.seal(derivedCaveatKey, secretKey: truncatedSignature)!
        
        caveats.append(Caveat(id: identifier, verificationId: verification, location: location))
        signatureBytes = signWithThirdPartyCaveat(verification, caveatId: identifier)
    }
    
    func serialize() -> String {
        var packets = [UInt8]()
        packets.appendContentsOf(packetize("location", data: [UInt8](location.utf8)))
        packets.appendContentsOf(packetize("identifier", data: [UInt8](identifier.utf8)))
        
        caveats.forEach { (c) -> () in
            packets.appendContentsOf(packetize("cid", data: [UInt8](c.id.utf8)))
            
            if c.verificationId != nil && c.location != nil {
                
                let count = c.verificationId!.length / sizeof(UInt8)
                var array = [UInt8](count: count, repeatedValue: 0)
                c.verificationId!.getBytes(&array, length:count * sizeof(UInt8))
                
                packets.appendContentsOf(packetize("vid", data: array))
                
                
                packets.appendContentsOf(packetize("cl", data: stringToIntArray(c.location!)))
            }
        }
        
        packets.appendContentsOf(packetize("signature", data: signatureBytes))
        return SwiftyBase64.EncodeString(packets, alphabet:.URLAndFilenameSafe).stringByReplacingOccurrencesOfString("=", withString: "")
    }
    
    private func signWithThirdPartyCaveat(verification: NSData, caveatId: String) -> [UInt8] {
        
        let count = verification.length / sizeof(UInt8)
        var array = [UInt8](count: count, repeatedValue: 0)
        verification.getBytes(&array, length:count * sizeof(UInt8))
        
        var verificationIdHash = hmac(key: signatureBytes, data: array)
        
        let caveatIdHash = hmac(key: signatureBytes, data: [UInt8](caveatId.utf8))
        
        verificationIdHash.appendContentsOf(caveatIdHash)
        
        return hmac(key: signatureBytes, data: verificationIdHash)
    }
    
    private func truncInt8ToNSData(array: [UInt8]) -> NSData {
        var result: [UInt8]
        if array.count > 32 {
            result = Array(array[0..<32])
        } else if array.count < 32 {
            var truncationResult = Array<UInt8>(count: 32 - array.count, repeatedValue: 0x00)
            truncationResult.insertContentsOf(array, at: 0)
            result = truncationResult
        } else {
            result = array
        }
        
        return NSData(bytes: result, length: result.count)
    }
    
    private func packetize(key: String, data: [UInt8]) -> [UInt8] {
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


