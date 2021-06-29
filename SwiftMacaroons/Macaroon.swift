import Foundation

public struct Macaroon {
    public var identifier: String
    public var location: String
    
    var signature: String {
        get { return Data(signatureBytes).toHex() }
    }
    
    public var signatureBytes: Data
    public var caveats: [Caveat]

    public init(identifier: String, location: String, caveats: [Caveat], signatureBytes: Data) {
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
        return serializeMacaroon(macaroon: self)
    }

    public func serializeV2(macaroon: Macaroon) -> String {
        return serializeMacaroonV2(macaroon: self)
    }

    public static func deserialize(_ base64Coded: String) -> Macaroon? {
        guard var decoded = decodeMacaroonString(base64Coded) else {
            return nil
        }

        if decoded[0] == 0x02 {
            return deserializeMacaroonV2(&decoded[1...])
        }

        return deserializeMacaroon(decoded)
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


