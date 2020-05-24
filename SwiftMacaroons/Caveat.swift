import Foundation

enum Caveat {
    case firstParty(id: String)
    case thirdParty(id: String, verificationId: Data, location: String)

    var id: String {
        switch self {
        case let .firstParty(id: id):
            return id
        case let .thirdParty(id: id, verificationId: _, location: _):
            return id
        }
    }
}
