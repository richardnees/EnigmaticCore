import Foundation
import CommonCrypto

extension Enigma {
    public func transform(_ transform: Enigma.Transform, data: Data, password: String) throws -> Data {
    
        let dataComponents = try prepare(transform: transform, data: data, password: password)

        // Create Key
        
        let saltBytes = [UInt8](dataComponents.salt)
        var key = Array<UInt8>(repeating: 0, count: kCCKeySizeAES128)
        let keyStatus = CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            password,
            password.lengthOfBytes(using: .utf8),
            saltBytes,
            dataComponents.salt.count,
            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
            33333,
            &key,
            key.count)

        guard keyStatus == kCCSuccess else {
            throw EnigmaError.cryptoUndefined
        }

        let ivBytes = [UInt8](dataComponents.iv)

        // Decrypt/Encrypt
        
        var operation = CCOperation(kCCDecrypt)
        
        switch transform {
        case .encrypt:
            operation = CCOperation(kCCEncrypt)
        case .decrypt:
            operation = CCOperation(kCCDecrypt)
        }

        var possibleCryptor: CCCryptorRef? = nil
        let cryptorCreateStatus = CCCryptorCreateWithMode(
            operation,
            CCMode(kCCModeCBC),
            CCAlgorithm(kCCAlgorithmAES),
            CCPadding(ccPKCS7Padding),
            ivBytes,
            key,
            key.count,
            nil,
            0,
            0,
            0,
            &possibleCryptor)
        
        guard cryptorCreateStatus == kCCSuccess else {
            throw EnigmaError.cryptoUndefined
        }

        // Check cryptor

        guard let cryptor = possibleCryptor else {
            throw EnigmaError.cryptoUndefined
        }
        
        // Invoke cryptor

        let inputDataBytes = [UInt8](dataComponents.inputData)
        let needed = CCCryptorGetOutputLength(cryptor, dataComponents.inputData.count, true)
        var outputData = Data(count: needed)
        var updateLen: size_t = 0
        let updateStatus = outputData.withUnsafeMutableBytes({ (outputDataBytes: UnsafeMutablePointer<UInt8>) -> CCCryptorStatus in
            return CCCryptorUpdate(
                cryptor,
                inputDataBytes, inputDataBytes.count,
                outputDataBytes, outputData.count,
                &updateLen)
        })
        
        guard updateStatus == kCCSuccess else {
            throw EnigmaError.cryptoUndefined
        }

        // Release cryptor

        CCCryptorRelease(cryptor)

        switch transform {
        case .encrypt:
            return dataComponents.iv + dataComponents.salt + outputData
        case .decrypt:
            return outputData[..<updateLen]
        }
    }
}
