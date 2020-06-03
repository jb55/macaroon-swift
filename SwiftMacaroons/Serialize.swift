//
//  Serialize.swift
//  SwiftMacaroons
//
//  Created by William Casarin on 2020-06-01.
//  Copyright © 2020 Bearch Inc. All rights reserved.
//

import Foundation

enum FieldTag : Int {
    case eos = 0
    case location
    case identifier
    case verificationId
    case signature
}

struct PacketV2 {
    var tag: FieldTag
    var data: Data
}

let packetPrefixLength = 4

func packetizeCaveatV2(key: FieldTag, data: Data) -> Data {
    var buffer = serializeVarint(UInt64(key.rawValue))
    if key != .eos {
        buffer.append(serializeVarint(UInt64(data.count)))
        buffer.append(data)
    }

    return buffer
}

func serializeVarint(_ value: UInt64) -> Data {
    var buffer = Data()
    var val: UInt64 = value

    while val >= 0x80 {
        buffer.append((UInt8(truncatingIfNeeded: val) | 0x80))
        val >>= 7
    }

    buffer.append(UInt8(val))
    return buffer
}

public func parseUVarInt(_ data: inout Data) -> UInt64? {
    var value: UInt64   = 0
    var shifter: UInt64 = 0
    var index = 0

    repeat {
        let byte = data[data.startIndex ..< data.startIndex + 1]
        if byte.count != 1 {
            print("couldn't parse uvarint byte")
            return nil
        }

        let buf = data[data.startIndex]
        data = data[(data.startIndex + 1)...]

        if buf < 0x80 {
            if index > 9 || index == 9 && buf > 1 {
                return nil
            }
            return value | UInt64(buf) << shifter
        }
        value |= UInt64(buf & 0x7f) << shifter
        shifter += 7
        index += 1
    } while true
}


func depacketizeCaveat(packet: Data) -> (String, Data)? {
    // find space break
    guard let breakAt = packet.firstIndex(of: 0x20) else {
        print("Macaroon.depacketize: no space found in \(packet.toHex())")
        return nil
    }

    let key = packet[..<breakAt]
    let val = packet[(breakAt+1)...]

    guard let keyStr = String(bytes: key, encoding: .utf8) else {
        print("Macaroon.depacketize: invalid key \(Array(key).data.toHex())")
        return nil
    }

    return (keyStr, val.dropLast())
}


public func decodeMacaroonString(_ base64Coded: String) -> Data? {
    guard let decoded = Base64.decode(base64Coded) else {
        // TODO: return errors
        print("macaroon base64 decode failed: '\(base64Coded)'")
        return nil
    }

    return decoded
}

func parseVarInt(_ data: inout Data) -> UInt64? {
    guard let val = parseUVarInt(&data) else {
        return nil
    }

    // too big or small
    if val > 0x7fffffff || val < 0 {
        return nil
    }

    return val
}

func parseTag(_ data: inout Data) -> FieldTag? {
    guard let rawTag = parseVarInt(&data) else {
        print("parsePacketV2: could not parse varint length")
        return nil
    }

    guard let tag = FieldTag(rawValue: Int(rawTag)) else {
        print("Invalid field tag: \(rawTag)")
        return nil
    }

    return tag
}

func parsePacketV2(_ data: inout Data, maxPayloadSize: Int = 4096) -> PacketV2? {
    guard let tag = parseTag(&data) else {
        return nil
    }

    if tag == .eos {
        return PacketV2(tag: .eos, data: Data())
    }

    guard let payloadLen = (parseVarInt(&data).map { Int($0) }) else {
        print("Couldn't parse packet v2 payload length")
        return nil
    }

    // something reasonable...
    if payloadLen > maxPayloadSize {
        print("Payload too large: \(payloadLen) > \(maxPayloadSize)")
        return nil
    }

    let p = data[data.startIndex..<data.startIndex+payloadLen]
    data = data[(data.startIndex+payloadLen)...]

    if p.count != payloadLen {
        print("Did not read expected payload length")
        return nil
    }

    return PacketV2(tag: tag, data: p)
}

func parsePacketsV2(_ data: inout Data) -> [PacketV2]? {
    var prevFieldType: FieldTag = .eos
    var packets: [PacketV2] = []

    while true {
        guard let packet = parsePacketV2(&data) else {
            print("packetv2 parse failed")
            return nil
        }

        if packet.tag == .eos {
            return packets
        }

        if packet.tag.rawValue <= prevFieldType.rawValue {
            print("fields out of order")
            return nil
        }

        packets.append(packet)
        prevFieldType = packet.tag
    }
}

public func deserializeMacaroonV2(_ data: inout Data) -> Macaroon? {
    guard var packets = parsePacketsV2(&data) else {
        print("failed to parse v2 header packets")
        return nil
    }

    var macLoc: String = ""
    if packets.count > 0 && packets[0].tag == .location {
        guard let loc = String(bytes: packets[0].data, encoding: .utf8) else {
            print("could not decode location as utf8")
            return nil
        }
        macLoc = loc
        packets.removeFirst()
    }
    else {
        print("Expected location in macaroon header")
        return nil
    }

    if packets.count != 1 || packets[0].tag != .identifier {
        print("invalid macaroon header")
        return nil
    }

    guard let macId = String(data: packets[0].data, encoding: .utf8) else {
        print("couldn't decode macaroon id as utf8")
        return nil
    }

    var identifier: String = ""
    var location: String? = nil
    var caveats: [Caveat] = []

    while true {
        guard var packets = parsePacketsV2(&data) else {
            print("failed to parse v2 body packets")
            return nil
        }

        if packets.count == 0 {
            break
        }

        if packets.count > 0 && packets[0].tag == .location {
            guard let loc = String(data: packets[0].data, encoding: .utf8) else {
                print("Could not decode caveat location")
                return nil
            }
            location = loc

            packets.removeFirst()
        }

        if packets.count == 0 || packets[0].tag != .identifier {
            print("no identifier in caveat")
            return nil
        }

        guard let ident = String(data: packets[0].data, encoding: .utf8) else {
            print("could not decode identifier")
            return nil
        }

        identifier = ident
        packets.removeFirst()

        if packets.count == 0 {
            // first party caveat
            if location != nil {
                print("location not allowed in first party caveat")
                return nil
            }
            caveats.append(.firstParty(id: identifier))
            continue
        }

        if packets.count != 1 {
            print("extract fields found in caveat")
            return nil
        }

        if packets[0].tag == .verificationId {
            print("invalid field found in caveat")
            return nil
        }

        guard let loc = location else {
            print("Expected location in third party caveat")
            return nil
        }

        caveats.append(.thirdParty(id: identifier, verificationId: packets[0].data, location: loc))
    }

    let signature = Data()

    return Macaroon(identifier: macId, location: macLoc, caveats: caveats, signatureBytes: signature)
}

public func deserializeMacaroon(_ data: Data) -> Macaroon? {
    var index = 0

    var location: String = ""
    var identifier: String = ""
    var signatureBytes: Data = Data()
    var caveats: [Caveat] = []

    let mcid : String? = nil
    let mvid : Data? = nil
    let mcl : String? = nil

    while index < data.count {
        let str = data[index..<(index + packetPrefixLength)].toString()

        let packetLength = Int(str, radix: 16)!
        let packet = data[(index + packetPrefixLength)..<(index + packetLength)]

        guard let tuple = depacketizeCaveat(packet: packet) else {
            return nil
        }

        switch (tuple.0) {
        case "location":
            guard let loc = String(bytes: tuple.1, encoding: .utf8) else {
                print("location not utf-8 string: '\(tuple.1.toHex())'")
                return nil
            }
            location = loc
        case "identifier":
            guard let ident = String(bytes: tuple.1, encoding: .utf8) else {
                print("identifier not utf-8 string: '\(tuple.1.toHex())'")
                return nil
            }
            identifier = ident
        case "signature":
            signatureBytes = tuple.1
        case "cid":
            guard let caveatId = String(bytes: tuple.1, encoding: .utf8) else {
                print("caveat id not utf-8 string: '\(tuple.1.toHex())'")
                return nil
            }
            caveats.append(.firstParty(id: caveatId))
            // TODO: third party caveats
            //case "vid":
            //    mvid = tuple.1
            //case "cl":
            //    guard let loc = String(bytes: tuple.1, encoding: .utf8) else {
            //        print("cl not utf-8 string: '\(tuple.1.toHex())'")
            //        return nil
            //    }
        //    mcl = loc
        default:
            print("unknown macaroon field: \(tuple.0)")
        }

        index += packetLength
    }

    switch (mcid, mvid, mcl) {
    case (.some(let cid), nil, nil):
        caveats.append(.firstParty(id: cid))
    case let (.some(cid), .some(vid), .some(cl)):
        caveats.append(.thirdParty(id: cid, verificationId: vid, location: cl))
    case _:
        break
    }

    return Macaroon(identifier: identifier,
                    location: location,
                    caveats: caveats,
                    signatureBytes: signatureBytes)
}

public func serializeMacaroonV2(macaroon: Macaroon) -> String {
    var packets = Data()
    packets.append(contentsOf: packetizeCaveatV2(key: .location, data: macaroon.location.data(using: .utf8)!))
    packets.append(contentsOf: packetizeCaveatV2(key: .identifier, data: macaroon.identifier.data(using: .utf8)!))

    macaroon.caveats.forEach { serializeCaveatV2(caveat: $0, intoPackets: &packets) }

    packets.append(contentsOf: packetizeCaveatV2(key: .signature, data: macaroon.signatureBytes))
    return Base64.encode(Data(packets))
}

func packetizeCaveat(key: String, data: Data) -> Data {
    let packet_size = packetPrefixLength + 2 + key.count + data.count
    var header = String(packet_size, radix: 16)

    while header.count < 4 {
        header = "0".appending(header)
    }

    var content = "\(key) ".toInt8()
    content.append(contentsOf: data)
    content.append(contentsOf: "\n".toInt8())

    var result = header.toInt8()
    result.append(contentsOf: content)
    return result.data
}

public func serializeCaveat(caveat: Caveat, intoPackets packets: inout Data) {
    packets.append(contentsOf: packetizeCaveat(key: "cid", data: caveat.id.data(using: .utf8)!))

    switch caveat {
    case let .thirdParty(_, verificationId, location):
        packets.append(contentsOf: packetizeCaveat(key: "vid", data: verificationId))
        packets.append(contentsOf: packetizeCaveat(key: "cl", data: location.data(using: .utf8)!))
    case .firstParty(_):
        break
    }
}

public func serializeMacaroon(macaroon: Macaroon) -> String {
    var packets = Data()
    packets.append(contentsOf: packetizeCaveat(key: "location", data: macaroon.location.data(using: .utf8)!))
    packets.append(contentsOf: packetizeCaveat(key: "identifier", data: macaroon.identifier.data(using: .utf8)!))

    macaroon.caveats.forEach { serializeCaveat(caveat: $0, intoPackets: &packets) }

    packets.append(contentsOf: packetizeCaveat(key: "signature", data: macaroon.signatureBytes))
    return Base64.encode(Data(packets))
}


public func serializeCaveatV2(caveat: Caveat, intoPackets packets: inout Data) {
    packets.append(contentsOf: packetizeCaveatV2(key: .identifier, data: caveat.id.data(using: .utf8)!))

    switch caveat {
    case let .thirdParty(_, verificationId, location):
        packets.append(contentsOf: packetizeCaveatV2(key: .verificationId, data: verificationId))
        packets.append(contentsOf: packetizeCaveatV2(key: .location, data: location.data(using: .utf8)!))
    case .firstParty(_):
        break
    }
}

