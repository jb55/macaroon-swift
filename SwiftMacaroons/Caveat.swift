import Foundation

public enum Caveat {
    case firstParty(id: String)
    case thirdParty(id: String, verificationId: Data, location: String)

    public var id: String {
        switch self {
        case let .firstParty(id: id):
            return id
        case let .thirdParty(id: id, verificationId: _, location: _):
            return id
        }
    }
}
