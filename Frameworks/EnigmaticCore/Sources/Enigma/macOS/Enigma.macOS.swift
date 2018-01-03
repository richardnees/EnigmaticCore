import Foundation

extension Enigma {
    
    public func transform(_ transform: Enigma.Transform, data: Data, password: String) throws -> Data {
        
        let dataComponents = try prepare(transform: transform, data: data, password: password)

        // Create Key

        var error: Unmanaged<CFError>?

        var parameters : [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeAES,
            kSecAttrPRF: kSecAttrPRFHmacAlgSHA256,
            kSecAttrRounds: 33333,
            kSecAttrKeySizeInBits: 128
        ]
        
        parameters[kSecAttrSalt] = dataComponents.salt
        
        guard let key = SecKeyDeriveFromPassword(password as CFString, parameters as CFDictionary, &error) else {
            throw EnigmaError.handle(unmanagedError: error)
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
        
        guard SecTransformSetAttribute(secTransform, kSecIVKey, dataComponents.iv as CFData, &error) else {
            throw EnigmaError.handle(unmanagedError: error)
        }
        
        guard SecTransformSetAttribute(secTransform, kSecTransformInputAttributeName, dataComponents.inputData as CFData, &error) else {
            throw EnigmaError.handle(unmanagedError: error)
        }
        
        // Execute Transform
        
        let result = SecTransformExecute(secTransform, &error)
        
        guard
            error == nil,
            let outputData = result as? Data
            else {
                throw EnigmaError.handle(unmanagedError: error)
        }
        
        // Return Data
        
        switch transform {
        case .encrypt:
            return dataComponents.iv + dataComponents.salt + outputData
        case .decrypt:
            return outputData
        }
    }
}

