import UIKit

//let b = "aa".trunc(11)

//b

let c:[UInt8] = [0x01, 0x02]
var r = Array<UInt8>(count: 32 - c.count, repeatedValue: 0x00)
r.insertContentsOf(c, at: 0)

r.count