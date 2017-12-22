import Foundation

extension Enigma {
    public struct Salt: RawRepresentable {
        public var rawValue: [UInt8]
        public init(rawValue: [UInt8]) {
            self.rawValue = rawValue
        }
    }
}

extension Enigma.Salt {
    public var dataValue: Data {
        return Data(bytes: rawValue)
    }
}

extension Enigma.Salt {
    public static func random(length: Enigma.Salt.Length) -> Enigma.Salt {
        var randomBytes = [UInt8](repeating: 0, count: length.rawValue)
        let _ = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
        return Enigma.Salt(rawValue: randomBytes)
    }
}

extension Enigma.Salt {
    public struct Length: RawRepresentable {
        public var rawValue: Int
        public init(rawValue: Int) {
            self.rawValue = rawValue
        }
    }
}

extension Enigma.Salt.Length {
    public static let `default` = Enigma.Salt.Length(rawValue: 32)
}
