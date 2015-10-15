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

//func ==(left: Caveat?, right: Caveat?) -> Bool {
//	
//	if left == nil {
//		return false
//	}
//
//	if right == nil {
//		return false
//	}
//	
//	if left!.id != right!.id {
//		return false
//	}
//	
//	if left!.verificationId != right!.verificationId {
//		return false
//	}
//	
//	if left!.location != right!.location {
//		return false
//	}
//	
//	return true
//}
