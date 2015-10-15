import UIKit
import CryptoSwift

//let b = "aa".trunc(11)

//b

let c:[UInt8] = [0x30, 0x30, 0x31, 0x63]

let str = String.init(bytes: c, encoding: NSUTF8StringEncoding)
Int.init(str!, radix: 16)

//28

//"001c"


//48, 48, 49, 99