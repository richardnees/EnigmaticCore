import Foundation

extension Enigma {
    public typealias IV = InitializationVector
    public struct InitializationVector: RawRepresentable {
        public var rawValue: [UInt8]
        public init(rawValue: [UInt8]) {
            self.rawValue = rawValue
        }
    }
}

extension Enigma.IV {
    public var dataValue: Data {
        return Data(bytes: rawValue)
    }
}

extension Enigma.IV {
    public static func random(length: Enigma.IV.Length) -> Enigma.IV {
        var randomBytes = [UInt8](repeating: 0, count: length.rawValue)
        let _ = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
        return Enigma.IV(rawValue: randomBytes)
    }
}

extension Enigma.IV {
    public struct Length: RawRepresentable {
        public var rawValue: Int
        public init(rawValue: Int) {
            self.rawValue = rawValue
        }
    }
}

extension Enigma.IV.Length {
    public static let `default` = Enigma.IV.Length(rawValue: 16)
}
