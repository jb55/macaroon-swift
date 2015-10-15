import Foundation

class Caveat {
    
    let id: String
    var verificationId: [UInt8]?
    var location: String?
    
    
    init(id: String, verificationId: [UInt8]? = nil, location: String? = nil) {
        self.id = id
        self.verificationId = verificationId
        self.location = location
    }

}