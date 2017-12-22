import Foundation

extension Enigma {
    public struct ConfigurationKey: RawRepresentable {
        public var rawValue: String
        public init(rawValue: String) {
            self.rawValue = rawValue
        }
    }
}

extension Enigma.ConfigurationKey: Hashable {
    public var hashValue: Int {
        return rawValue.hashValue
    }
}

extension Enigma.ConfigurationKey {
    public static let ivLength = Enigma.ConfigurationKey(rawValue: "ivLength")
    public static let saltLength = Enigma.ConfigurationKey(rawValue: "saltLength")
}
