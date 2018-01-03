import Foundation
import Security

let EnigmaDefaultIVLength = Enigma.IV.Length.default.rawValue
let EnigmaDefaultSaltLength = Enigma.Salt.Length.default.rawValue

public struct Enigma {
    
    public static var defaultConfiguration: [Enigma.ConfigurationKey: Any] = [
        .ivLength : Enigma.IV.Length.default,
        .saltLength : Enigma.Salt.Length.default
    ]
    
    func prepare(transform: Enigma.Transform, data: Data, password: String) throws -> (iv: Data, salt: Data, inputData: Data) {
        
        // Check password
        
        guard password.isEmpty == false else {
            throw EnigmaError.noPassword
        }
        
        // Prepare Data
        
        var inputData = Data()
        
        switch transform {
        case .encrypt:
            inputData = data
        case .decrypt:
            guard data.count > (EnigmaDefaultIVLength + EnigmaDefaultSaltLength) else {
                throw EnigmaError.noData
            }
            inputData = data[(EnigmaDefaultIVLength + EnigmaDefaultSaltLength)...]
        }
        
        // Salt
        
        var salt = Data()
        
        switch transform {
        case .encrypt:
            salt = Enigma.Salt.random(length: .default).dataValue
        case .decrypt:
            salt = data[EnigmaDefaultIVLength...(EnigmaDefaultIVLength + EnigmaDefaultSaltLength - 1)]
        }
        
        // IV
        
        var iv = Data()
        
        switch transform {
        case .encrypt:
            iv = Enigma.IV.random(length: .default).dataValue
        case .decrypt:
            iv = data[...(EnigmaDefaultIVLength - 1)]
        }
        
        return (iv: iv, salt: salt, inputData: inputData)
    }
}
