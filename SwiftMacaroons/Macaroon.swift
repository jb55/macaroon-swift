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
    
    private let packetPrefixLength = 4
    
    init(key: String, identifier: String, location: String) {
        self.key = key.toInt8()
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
    
    func serialize() -> String {
        var packets = [UInt8]()
        packets.appendContentsOf(packetize("location", data: location.toInt8()))
        packets.appendContentsOf(packetize("identifier", data: identifier.toInt8()))
        
        caveats.forEach { serializeCaveat($0, intoPackets: &packets) }
        
        packets.appendContentsOf(packetize("signature", data: signatureBytes))
        return SwiftyBase64.EncodeString(packets, alphabet:.URLAndFilenameSafe).stringByReplacingOccurrencesOfString("=", withString: "")
    }
    
    func serializeCaveat(caveat: Caveat, inout intoPackets packets: [UInt8]) {
        packets.appendContentsOf(packetize("cid", data: caveat.id.toInt8()))
        
        if caveat.isThirdParty() {
            packets.appendContentsOf(packetize("vid", data: caveat.verificationId!))
            packets.appendContentsOf(packetize("cl", data: caveat.location!.toInt8()))
        }
    }
    
    func deserialize(var base64Coded: String) {
        let numberOfEqualsInTheEnd = (4 - (base64Coded.lengthOfBytesUsingEncoding(NSUTF8StringEncoding) % 4)) % 4
        for _ in 0..<numberOfEqualsInTheEnd {
            base64Coded.append("=" as Character)
        }
        
        let decodedUInt8 = Crypto.base64UrlSafeDecode(base64Coded)
        var index = 0
        
        while index < decodedUInt8.count {
			
            let str = decodedUInt8[index..<(index + packetPrefixLength)].toString()

            let packetLength = Int(str, radix: 16)!
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
                self.caveats.last!.location = (tuple.1 as! String)
			default:
				print("o bixo pegou")
			}
			
			index += packetLength
        }
    }
    
	func depacketize(packet: [UInt8]) -> (String, AnyObject) {
        if Array(packet[0..<3]) == "vid".toInt8() {
            return ("vid", NSData.withBytes(Array(packet[4..<packet.count - 1])))
        }
		
		if Array(packet[0..<9]) == "signature".toInt8() {
			return ("signature", NSData.withBytes(Array(packet[10..<packet.count - 1])))
		}
        
        let packet = packet.toString()
        let splitString = packet.componentsSeparatedByString(" ")
        let key = splitString[0]
        let value = Array(splitString[1..<splitString.count]).joinWithSeparator(" ")
        
        return (key, value.stringByReplacingOccurrencesOfString("\n", withString:""))
    }
    
    private func packetize(key: String, data: [UInt8]) -> [UInt8] {
        let packet_size = packetPrefixLength + 2 + key.characters.count + data.count
        var header = String(packet_size, radix: 16)
        
        while header.characters.count < 4 {
            header = "0".stringByAppendingString(header)
        }
        
        var content = "\(key) ".toInt8()
        content.appendContentsOf(data)
        content.appendContentsOf("\n".toInt8())
        
        var result = header.toInt8()
        result.appendContentsOf(content)
        return result
    }
    
    func prepareForRequest(macaroon: Macaroon) -> Macaroon {
        let result = Macaroon(bytes: self.serialize())
        result.signatureBytes = MacaroonCrypto.bindSignature(self.signatureBytes, with: macaroon.signatureBytes)
        return result
    }
    
    func addFirstPartyCaveat(predicate: String) {
        caveats.append(Caveat(id: predicate))
        signatureBytes = Crypto.hmac(key: signatureBytes, data: predicate.toInt8())
    }
    
    func addThirdPartyCaveat(location: String, verificationId: String, identifier: String) {
        let verification = MacaroonCrypto.createVerificationId(verificationId.toInt8(), signature: signatureBytes)
        
        caveats.append(Caveat(id: identifier, verificationId: verification, location: location))
        signatureBytes = MacaroonCrypto.signWithThirdPartyCaveat(verification, caveatId: identifier.toInt8(), signature: signatureBytes)
    }
    
    private func createSignature() -> [UInt8] {
        return MacaroonCrypto.initialSignature(key, identifier: identifier.toInt8())
    }
}


