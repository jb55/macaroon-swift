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