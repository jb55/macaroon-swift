import Foundation

struct Macaroon {
    var identifier: String
    var location: String
    
    var signature: String {
        get { return Data(signatureBytes).toHex() }
    }
    
    var signatureBytes: Data
    var caveats: [Caveat]
    
    static let packetPrefixLength = 4

    private init(identifier: String, location: String, caveats: [Caveat], signatureBytes: Data) {
        self.identifier = identifier
        self.location = location
        self.caveats = caveats
        self.signatureBytes = signatureBytes
    }

    public init(key: Data, identifier: String, location: String) {
        self.identifier = identifier
        self.location = location
        self.caveats = []
        self.signatureBytes = Data()
        self.signatureBytes = self.createSignature(key: key)
    }

    public init(other: Macaroon) {
        self.identifier = other.identifier
        self.location = other.location
        self.signatureBytes = other.signatureBytes
        self.caveats = other.caveats
    }
    
    public func serialize() -> String {
        var packets = Data()
        packets.append(contentsOf: Macaroon.packetize(key: "location", data: location.data(using: .utf8)!))
        packets.append(contentsOf: Macaroon.packetize(key: "identifier", data: identifier.data(using: .utf8)!))
        
        caveats.forEach { Macaroon.serializeCaveat(caveat: $0, intoPackets: &packets) }
        
        packets.append(contentsOf: Macaroon.packetize(key: "signature", data: signatureBytes))
        return Base64.encode(Data(packets))
        //return SwiftyBase64.EncodeString(packets, alphabet:.URLAndFilenameSafe).stringByReplacingOccurrencesOfString("=", withString: "")
    }
    
    public static func serializeCaveat(caveat: Caveat, intoPackets packets: inout Data) {
        packets.append(contentsOf: packetize(key: "cid", data: caveat.id.data(using: .utf8)!))

        switch caveat {
        case let .thirdParty(_, verificationId, location):
            packets.append(contentsOf: packetize(key: "vid", data: verificationId))
            packets.append(contentsOf: packetize(key: "cl", data: location.data(using: .utf8)!))
        case .firstParty(_):
            break
        }
    }

    public static func deserialize(_ base64Coded: String) -> Macaroon? {
        guard let decoded = Base64.decode(base64Coded) else {
            // TODO: return errors
            print("macaroon base64 decode failed: '\(base64Coded)'")
            return nil
        }
        var index = 0

        var location: String = ""
        var identifier: String = ""
        var signatureBytes: Data = Data()
        var caveats: [Caveat] = []
        
        let mcid : String? = nil
        let mvid : Data? = nil
        let mcl : String? = nil
        
        while index < decoded.count {
            let str = decoded[index..<(index + packetPrefixLength)].toString()

            let packetLength = Int(str, radix: 16)!
			let packet = decoded[(index + packetPrefixLength)..<(index + packetLength)]

            guard let tuple = depacketize(packet: packet) else {
                return nil
            }
			
			switch (tuple.0) {
			case "location":
                guard let loc = String(bytes: tuple.1, encoding: .utf8) else {
                    print("location not utf-8 string: '\(tuple.1.toHex())'")
                    return nil
                }
                location = loc
			case "identifier":
                guard let ident = String(bytes: tuple.1, encoding: .utf8) else {
                    print("identifier not utf-8 string: '\(tuple.1.toHex())'")
                    return nil
                }
                identifier = ident
			case "signature":
                signatureBytes = tuple.1
            case "cid":
                guard let caveatId = String(bytes: tuple.1, encoding: .utf8) else {
                    print("caveat id not utf-8 string: '\(tuple.1.toHex())'")
                    return nil
                }
                caveats.append(.firstParty(id: caveatId))
                // TODO: third party caveats
            //case "vid":
            //    mvid = tuple.1
            //case "cl":
            //    guard let loc = String(bytes: tuple.1, encoding: .utf8) else {
            //        print("cl not utf-8 string: '\(tuple.1.toHex())'")
            //        return nil
            //    }
            //    mcl = loc
			default:
				print("unknown macaroon field: \(tuple.0)")
			}
			
			index += packetLength
        }

        switch (mcid, mvid, mcl) {
        case (.some(let cid), nil, nil):
            caveats.append(.firstParty(id: cid))
        case let (.some(cid), .some(vid), .some(cl)):
            caveats.append(.thirdParty(id: cid, verificationId: vid, location: cl))
        case _:
            break
        }

        return Macaroon(identifier: identifier,
                        location: location,
                        caveats: caveats,
                        signatureBytes: signatureBytes)
    }
    
	static func depacketize(packet: Data) -> (String, Data)? {
        // find space break
        guard let breakAt = packet.firstIndex(of: 0x20) else {
            print("Macaroon.depacketize: no space found in \(packet.toHex())")
            return nil
        }

        let key = packet[..<breakAt]
        let val = packet[(breakAt+1)...]

        guard let keyStr = String(bytes: key, encoding: .utf8) else {
            print("Macaroon.depacketize: invalid key \(Array(key).data.toHex())")
            return nil
        }

        return (keyStr, val.dropLast())
    }

    static private func packetize(key: String, data: Data) -> Data {
        let packet_size = Macaroon.packetPrefixLength + 2 + key.count + data.count
        var header = String(packet_size, radix: 16)
        
        while header.count < 4 {
            header = "0".appending(header)
        }
        
        var content = "\(key) ".toInt8()
        content.append(contentsOf: data)
        content.append(contentsOf: "\n".toInt8())
        
        var result = header.toInt8()
        result.append(contentsOf: content)
        return result.data
    }
    
    public mutating func addFirstPartyCaveat(_ predicate: String) {
        caveats.append(.firstParty(id: predicate))
        signatureBytes =
            HMAC.hmac(key: signatureBytes,
                data: predicate.toInt8().data,
                algo: HMACAlgo.SHA256)
    }
    
   // func addThirdPartyCaveat(location: String, verificationId: String, identifier: String) {
   //     let verification = MacaroonCrypto.createVerificationId(verificationId.toInt8(), signature: signatureBytes)
   //
   //     caveats.append(Caveat(id: identifier, verificationId: verification, location: location))
   //     signatureBytes = MacaroonCrypto.signWithThirdPartyCaveat(verification, caveatId: identifier.toInt8(), signature: signatureBytes)
   // }
   //
    private func createSignature(key: Data) -> Data {
        let ident = identifier.data(using: .utf8)!
        return MacaroonCrypto.initialSignature(key: key, identifier: ident)
    }
}


