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
    
    func deserialize(bytes: String) {
        var result = bytes
        let numberOfEqualsInTheEnd = (4 - (bytes.lengthOfBytesUsingEncoding(NSUTF8StringEncoding) % 4)) % 4
        for _ in 1...numberOfEqualsInTheEnd {
            result.append("=" as Character)
        }
        
        //http://ruby-doc.org/stdlib-2.2.3/libdoc/base64/rdoc/Base64.html#method-i-urlsafe_decode64
        result = result.stringByReplacingOccurrencesOfString("-", withString: "+")
        result = result.stringByReplacingOccurrencesOfString("_", withString: "/")
        
        
        let decoded = NSData(base64EncodedString: result, options: NSDataBase64DecodingOptions(rawValue: 0))
        
        let count = decoded!.length / sizeof(UInt8)
        var decodedUInt8 = [UInt8](count: count, repeatedValue: 0)
        decoded!.getBytes(&decodedUInt8, length:count * sizeof(UInt8))
        
        var index = 0
        
        while index < decoded?.length {
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
				let signature = tuple.1 as! NSData
				let count = signature.length / sizeof(UInt8)
				var array = [UInt8](count: count, repeatedValue: 0)
				signature.getBytes(&array, length:count * sizeof(UInt8))
				self.signatureBytes = array
            case "cid":
                self.caveats.append(Caveat(id: tuple.1 as! String))
            case "vid":
                self.caveats.last!.verificationId = tuple.1 as! NSData
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
            result = Array<UInt8>(count: 32 - array.count, repeatedValue: 0x00)
            result.insertContentsOf(array, at: 0)
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
}


