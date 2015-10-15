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
    
    private let magicMacaroonKey = "macaroons-key-generator".toInt8()
    private let packetPrefixLength = 4
    
    init(key: String, identifier: String, location: String) {
        self.key = [UInt8](key.utf8)
        self.identifier = identifier
        self.location = location
        self.caveats = []
        self.signatureBytes = self.createSignature()
    }
    
    init(bytes: String) {
        self.key = [UInt8]()
        self.identifier = ""
        self.location = ""
        self.caveats = []
        self.signatureBytes = [UInt8]()
        self.deserialize(bytes)
    }
    
    func addFirstPartyCaveat(predicate: String) {
        caveats.append(Caveat(id: predicate))
        signatureBytes = hmac(key: signatureBytes, data: predicate.toInt8())
    }

    func addThirdPartyCaveat(location: String, verificationId: String, identifier: String) {
        let caveatKey = hmac(key: magicMacaroonKey, data: verificationId.toInt8())
        
        let derivedCaveatKey = caveatKey.trunc(32)
        let truncatedSignature = signatureBytes.trunc(32)
        let verification = secretBox(derivedCaveatKey, secretKey: truncatedSignature)
        
        caveats.append(Caveat(id: identifier, verificationId: verification, location: location))
        signatureBytes = signWithThirdPartyCaveat(verification, caveatId: identifier)
    }
    
    func serialize() -> String {
        var packets = [UInt8]()
        packets.appendContentsOf(packetize("location", data: location.toInt8()))
        packets.appendContentsOf(packetize("identifier", data: identifier.toInt8()))
        
        caveats.forEach { (c) -> () in
            packets.appendContentsOf(packetize("cid", data: c.id.toInt8()))
            
            if c.verificationId != nil && c.location != nil {
                packets.appendContentsOf(packetize("vid", data: c.verificationId!))
                packets.appendContentsOf(packetize("cl", data: c.location!.toInt8()))
            }
        }
        
        packets.appendContentsOf(packetize("signature", data: signatureBytes))
        return SwiftyBase64.EncodeString(packets, alphabet:.URLAndFilenameSafe).stringByReplacingOccurrencesOfString("=", withString: "")
    }
    
    func deserialize(bytes: String) {
        var result = bytes
        let numberOfEqualsInTheEnd = (4 - (bytes.lengthOfBytesUsingEncoding(NSUTF8StringEncoding) % 4)) % 4
        for _ in 1...numberOfEqualsInTheEnd {
            result.append("=" as Character)
        }
        
        //http://ruby-doc.org/stdlib-2.2.3/libdoc/base64/rdoc/Base64.html#method-i-urlsafe_decode64
        result = result.stringByReplacingOccurrencesOfString("-", withString: "+")
        result = result.stringByReplacingOccurrencesOfString("_", withString: "/")
        
        let decodedUInt8 = NSData(base64EncodedString: result, options: NSDataBase64DecodingOptions(rawValue: 0))!.toInt8Array()
        
        var index = 0
        
        while index < decodedUInt8.count {
            let str = String(bytes: decodedUInt8[index..<(index + packetPrefixLength)], encoding: NSUTF8StringEncoding)

            let packetLength = Int(str!, radix: 16)!
			let packet = decodedUInt8[(index + packetPrefixLength)..<(index + packetLength)]
			let tuple = depacketize(Array(packet))
			
			switch (tuple.0) {
			case "location":
				self.location = tuple.1 as! String
			case "identifier":
				self.identifier = tuple.1 as! String
			case "signature":
				self.signatureBytes = (tuple.1 as! NSData).toInt8Array()
            case "cid":
                self.caveats.append(Caveat(id: tuple.1 as! String))
            case "vid":
                self.caveats.last!.verificationId = (tuple.1 as! NSData).toInt8Array()
            case "cl":
                self.caveats.last!.location = tuple.1 as! String
			default:
				print("o bixo pegou")
			}
			
			index += packetLength
			
			print("\(tuple)")
        }
    }
    
	func depacketize(packet: [UInt8]) -> (String, AnyObject) {
        
        var keyTest = String(bytes: packet[0..<3], encoding: NSUTF8StringEncoding)!
        
        if keyTest == "vid" {
            return ("vid", NSData.withBytes(Array(packet[4..<packet.count - 1])))
        }

		keyTest = String(bytes: packet[0..<9], encoding: NSUTF8StringEncoding)!
		
		if keyTest == "signature" {
			return ("signature", NSData.withBytes(Array(packet[10..<packet.count - 1])))
		}
        
        let packet = String(bytes: packet, encoding: NSUTF8StringEncoding)!
        let splitString = packet.componentsSeparatedByString(" ")
        let key = splitString[0]
        let value = Array(splitString[1..<splitString.count]).joinWithSeparator(" ")
        
        return (key, value.stringByReplacingOccurrencesOfString("\n", withString:""))
    }
    
    private func signWithThirdPartyCaveat(verification: [UInt8], caveatId: String) -> [UInt8] {
        var verificationIdHash = hmac(key: signatureBytes, data: verification)
        let caveatIdHash = hmac(key: signatureBytes, data: caveatId.toInt8())
        verificationIdHash.appendContentsOf(caveatIdHash)
        
        return hmac(key: signatureBytes, data: verificationIdHash)
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
        return hmac(key: derivedKey, data: identifier.toInt8())
    }
    
    private func generateDerivedKey() -> [UInt8] {
        return hmac(key: magicMacaroonKey, data: key)
    }
}


