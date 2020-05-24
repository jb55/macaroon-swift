
import Foundation
import CommonCrypto

// base64 encoding with no padding
public struct Base64 {
    static func encode(_ data: Data) -> String {
        return String(bytes: Base64Encode(data.bytes), encoding: .utf8)!
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }

    static func decode(_ b64url: String) -> Data? {
        var base64 = b64url
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        if base64.count % 4 != 0 {
            base64.append(String(repeating: "=", count: 4 - base64.count % 4))
        }

        return Data(base64Encoded: base64)
    }
}

public struct HMAC {
    public static func hmac(key: Data, data: Data, algo: HMACAlgo=HMACAlgo.SHA256) -> Data {
        let nsdata = data as NSData
        let nskey = key as NSData

        let res = hmacNSData(key: nskey, data: nsdata, algo: algo)
        return Data(referencing: res)
    }

    private static func hmacNSData(key: NSData, data: NSData, algo: HMACAlgo) -> NSData {
        let macOut = NSMutableData(length: algo.digestLength())!

        CCHmac(algo.ccHmacAlg(), key.bytes, key.count, data.bytes, data.count, macOut.mutableBytes)

        return macOut
    }

    static func hashString(_ inp: String, algo: HMACAlgo=HMACAlgo.SHA256) -> String? {
        if let stringData = inp.data(using: .utf8, allowLossyConversion: false) {
            return hash(stringData, algo: algo).toHex()
        }

        return nil
    }

    private static func hashBytes(_ input: [UInt8], algo: HMACAlgo) -> [UInt8] {
        return hash(input.toNSData(), algo: algo).toInt8Array()
    }

    private static func hash(_ input: Data, algo: HMACAlgo) -> Data {
        let nsdata = input as NSData;

        return Data(referencing: HMAC.hash(nsdata, algo: algo))
    }

    private static func hash(_ input: NSData, algo: HMACAlgo) -> NSData {
        let digestLength = algo.digestLength()
        var hash = [UInt8](repeating: 0, count: digestLength)
        switch algo {
        case .MD5: CC_MD5(input.bytes, UInt32(input.length), &hash)
        case .SHA1: CC_SHA1(input.bytes, UInt32(input.length), &hash)
        case .SHA224: CC_SHA224(input.bytes, UInt32(input.length), &hash)
        case .SHA256: CC_SHA256(input.bytes, UInt32(input.length), &hash)
        case .SHA384: CC_SHA384(input.bytes, UInt32(input.length), &hash)
        case .SHA512: CC_SHA512(input.bytes, UInt32(input.length), &hash)
        }
        return NSData(bytes: hash, length: digestLength)
    }

}

public enum HMACAlgo {

    case MD5, SHA1, SHA224, SHA256, SHA384, SHA512

    func ccHmacAlg() -> CCHmacAlgorithm {
        var result = CCHmacAlgorithm(kCCHmacAlgSHA256)

        switch self {
        case .MD5: result = CCHmacAlgorithm(kCCHmacAlgMD5)
        case .SHA1: result = CCHmacAlgorithm(kCCHmacAlgSHA1)
        case .SHA224: result = CCHmacAlgorithm(kCCHmacAlgSHA224)
        case .SHA256: result = CCHmacAlgorithm(kCCHmacAlgSHA256)
        case .SHA384: result = CCHmacAlgorithm(kCCHmacAlgSHA384)
        case .SHA512: result = CCHmacAlgorithm(kCCHmacAlgSHA512)
        }

        return result
    }

    func digestLength() -> Int {
        var result: CInt = 0
        switch self {
        case .MD5: result = CC_MD5_DIGEST_LENGTH
        case .SHA1: result = CC_SHA1_DIGEST_LENGTH
        case .SHA224: result = CC_SHA224_DIGEST_LENGTH
        case .SHA256: result = CC_SHA256_DIGEST_LENGTH
        case .SHA384: result = CC_SHA384_DIGEST_LENGTH
        case .SHA512: result = CC_SHA512_DIGEST_LENGTH
        }
        return Int(result)
    }
}
