import Foundation
import Security

private let EnigmaDefaultIVLength = Enigma.IV.Length.default.rawValue
private let EnigmaDefaultSaltLength = Enigma.Salt.Length.default.rawValue

public class Enigma: NSObject {
    
    public static var defaultParameters: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeAES,
        kSecAttrPRF: kSecAttrPRFHmacAlgSHA256,
        kSecAttrRounds: 33333,
        kSecAttrKeySizeInBits: 128
    ]

    public static var defaultConfiguration: [Enigma.ConfigurationKey: Any] = [
        .ivLength : Enigma.IV.Length.default,
        .saltLength : Enigma.Salt.Length.default
    ]
        
    public func transform(
        _ transform: Enigma.Transform,
        data: Data,
        password: String,
        parameters inputParameters: [CFString: Any] = defaultParameters,
        configuration: [Enigma.ConfigurationKey: Any] = [:] //defaultConfiguration
        ) throws -> Data {

        var error: Unmanaged<CFError>?
        
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
        
        // Create Key Parameters

        var salt = Data()

        switch transform {
        case .encrypt:
            salt = Enigma.Salt.random(length: .default).dataValue
        case .decrypt:
            salt = data[EnigmaDefaultIVLength...(EnigmaDefaultIVLength + EnigmaDefaultSaltLength - 1)]
        }

        var parameters = inputParameters
        parameters[kSecAttrSalt] = salt
        
        // Create Key

        guard let key = SecKeyDeriveFromPassword(password as CFString, parameters as CFDictionary, &error) else {
            throw EnigmaError.handle(unmanagedError: error)
        }

        // Create IV
        
        var iv = Data()

        switch transform {
        case .encrypt:
            iv = Enigma.IV.random(length: .default).dataValue
        case .decrypt:
            iv = data[...(EnigmaDefaultIVLength - 1)]
        }

        // Create Transform

        var potentialSecTransform: SecTransform?
        
        switch transform {
        case .encrypt:
            potentialSecTransform = SecEncryptTransformCreate(key, &error)
        case .decrypt:
            potentialSecTransform = SecDecryptTransformCreate(key, &error)
        }

        guard
            error == nil,
            let secTransform = potentialSecTransform
            else {
                throw EnigmaError.handle(unmanagedError: error)
        }

        // Add Transform Attributes

        guard SecTransformSetAttribute(secTransform, kSecEncryptionMode, kSecModeCBCKey, &error) else {
            throw EnigmaError.handle(unmanagedError: error)
        }

        guard SecTransformSetAttribute(secTransform, kSecPaddingKey, kSecPaddingPKCS7Key, &error) else {
            throw EnigmaError.handle(unmanagedError: error)
        }

        guard SecTransformSetAttribute(secTransform, kSecIVKey, iv as CFData, &error) else {
            throw EnigmaError.handle(unmanagedError: error)
        }

        guard SecTransformSetAttribute(secTransform, kSecTransformInputAttributeName, inputData as CFData, &error) else {
            throw EnigmaError.handle(unmanagedError: error)
        }
        
        // Execute Transform

        let cfType = SecTransformExecute(secTransform, &error)

        guard
            error == nil,
            let outputData = cfType as? Data
            else {
                throw EnigmaError.handle(unmanagedError: error)
        }

        // Return Data

        switch transform {
        case .encrypt:
            return iv + salt + outputData
        case .decrypt:
            return outputData
        }
    }
}
