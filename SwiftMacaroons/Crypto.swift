import Foundation
import CryptoSwift
import Sodium

func hmac(key key: [UInt8], data: [UInt8]) -> [UInt8] {
    let authenticator = Authenticator.HMAC(key: key, variant: HMAC.Variant.sha256)
    let hmacUInt = authenticator.authenticate(data)!
    return hmacUInt
}

func secretBox(message: [UInt8], secretKey: [UInt8]) -> [UInt8] {
    let messageData = message.toNSData()
    let secreteKeyData = secretKey.toNSData()
    let result:NSData = Sodium()!.secretBox.seal(messageData, secretKey: secreteKeyData)!
    return result.toInt8Array()
}

func base64UrlSafeDecode(coded: String) -> [UInt8] {
    //http://ruby-doc.org/stdlib-2.2.3/libdoc/base64/rdoc/Base64.html#method-i-urlsafe_decode64
    var result = coded.stringByReplacingOccurrencesOfString("-", withString: "+")
    result = result.stringByReplacingOccurrencesOfString("_", withString: "/")
    
    return NSData(base64EncodedString: result, options: NSDataBase64DecodingOptions(rawValue: 0))!.toInt8Array()
}