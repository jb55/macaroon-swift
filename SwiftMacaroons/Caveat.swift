import Foundation

class Caveat {
    
    let id: String
    let verificationId: String?
    let location: String?
    
    
    init(id: String, verificationId: String? = nil, location: String? = nil) {
        self.id = id
        self.verificationId = verificationId
        self.location = location
    }

}
