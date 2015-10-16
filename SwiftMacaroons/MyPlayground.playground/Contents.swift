import UIKit
import CryptoSwift

//let b = "aa".trunc(11)

//b

let c:[UInt8] = [0x30, 0x30, 0x31, 0x63, 0x00000000002f]

let str = String.init(bytes: c, encoding: NSUTF8StringEncoding)
Int.init(str!, radix: 16)

//28

//"001c"


//48, 48, 49, 99

let result = "MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIB7-R2PykNvODB0IR3Nn4R9O7kVqZJM89mLXl3LbuCEoCg="

let result2 = "MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAyZnNpZ25hdHVyZSDj2eApCFJsTAA5rhURQRXZf91ovyujebNCqvD2F9BVLwo===================="

NSData(base64EncodedString: result, options: NSDataBase64DecodingOptions(rawValue: 0))

let j  = Array<UInt8>(count: 0, repeatedValue: 0x00)