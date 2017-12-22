import Foundation

public class EnigmaTransformOperation: Operation {
    public let transform: Enigma.Transform
    public let password: String
    public var error: Error?

    public init(transform: Enigma.Transform, password: String) {
        self.transform = transform
        self.password = password
    }
}
