import Foundation

extension String {
    func trunc(length: Int) -> String {
        if self.characters.count > length {
            return self.substringToIndex(self.startIndex.advancedBy(length))
        } else if self.characters.count < length {
            var original = self
            while original.characters.count < length {
                original.appendContentsOf("\(0x00)")
            }
            
            return original
        }else {
            return self
        }
    }
    
    func toInt8() -> [UInt8] {
        return [UInt8](self.utf8)
    }
}

extension SequenceType where Generator.Element == UInt8 {
	func toString() -> String {
		return String(bytes: self, encoding: NSUTF8StringEncoding)!
	}
}

extension Array where Element : UnsignedIntegerType {
    func trunc(length: Int) -> [Element] {
        if self.count > length {
            return Array(self[0..<length])
        } else if self.count < length {
            var result = Array<Element>(count: length - self.count, repeatedValue: 0x00)
            result.insertContentsOf(self, at: 0)
            return result
        } else {
            return self
        }
    }
    
    func toNSData() -> NSData {
        return NSData(bytes: self, length: self.count)
    }
}

extension NSData {
    func toInt8Array() -> [UInt8] {
        let count = self.length / sizeof(UInt8)
        var array = [UInt8](count: count, repeatedValue: 0)
        self.getBytes(&array, length:count * sizeof(UInt8))
        return array
    }
}