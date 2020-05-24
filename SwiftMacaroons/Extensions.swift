import Foundation

extension String {
	func toInt8() -> [UInt8] {
		return [UInt8](self.utf8)
	}
}

extension Sequence where Element == UInt8 {
	func toString() -> String {
        return String(bytes: self, encoding: String.Encoding.utf8)!
	}
}

extension String {
    func fromBase64() -> String? {
        guard let data = Data(base64Encoded: self) else {
            return nil
        }

        return String(data: data, encoding: .utf8)
    }

    func toBase64() -> String {
        return Data(self.utf8).base64EncodedString()
    }
}

extension Array where Element : UnsignedInteger {
	func trunc(length: Int) -> [Element] {
		if self.count > length {
			return Array(self[0..<length])
		}
		
        var result = Array<Element>(repeating: 0, count: length - self.count)
        result.insert(contentsOf: self, at: 0)
		return result
	}
	
	func toNSData() -> NSData {
		return NSData(bytes: self, length: self.count)
	}
}

extension Array where Element == UInt8 {
    var data : Data{
        return Data(self)
    }
}

extension Data {
    /// A hexadecimal string representation of the bytes.
    func toHex() -> String {
        let hexDigits = Array("0123456789abcdef".utf16)
        var hexChars = [UTF16.CodeUnit]()
        hexChars.reserveCapacity(count * 2)

        for byte in self {
            let (index1, index2) = Int(byte).quotientAndRemainder(dividingBy: 16)
            hexChars.append(hexDigits[index1])
            hexChars.append(hexDigits[index2])
        }

        return String(utf16CodeUnits: hexChars, count: hexChars.count)
    }

    var bytes : [UInt8] {
        return [UInt8](self)
    }
}

extension NSData {
	func toInt8Array() -> [UInt8] {
        var array = [UInt8](repeating: 0, count: count)
		self.getBytes(&array, length:count)
		return array
	}
}
