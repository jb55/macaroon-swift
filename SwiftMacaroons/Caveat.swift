import Foundation

class Caveat {
    
    let id: String
    let verificationId: NSData?
    let location: String?
    
    
    init(id: String, verificationId: NSData? = nil, location: String? = nil) {
        self.id = id
        self.verificationId = verificationId
        self.location = location
    }

}
