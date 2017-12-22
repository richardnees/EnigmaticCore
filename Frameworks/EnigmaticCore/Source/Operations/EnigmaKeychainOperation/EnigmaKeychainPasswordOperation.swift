import Foundation

public class EnigmaKeychainPasswordOperation: Operation {
    public var service: String = "Enigma"
    public var label: String = Bundle.main.bundleIdentifier ?? "com.richardnees.Enigma.script"
    public var data: Data?
    public var error: Error?
    public var password: String?
    
    var defaultQuery: [CFString: Any] {
        return [
            kSecClass: kSecClassGenericPassword,
            kSecAttrLabel: label,
            kSecAttrService: service
        ]
    }
}
