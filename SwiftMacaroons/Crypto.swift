import Foundation
import CryptoSwift
import Sodium

func hmac(key key: [UInt8], data: [UInt8]) -> [UInt8] {
    let authenticator = Authenticator.HMAC(key: key, variant: HMAC.Variant.sha256)
    let hmacUInt = authenticator.authenticate(data)!
    return hmacUInt
}

//func secretBox(message: [UInt8], data: [UInt8]) -> [UInt8] {
//    let result = Sodium()!.secretBox.seal(derivedCaveatKey, secretKey: truncatedSignature)!
//}