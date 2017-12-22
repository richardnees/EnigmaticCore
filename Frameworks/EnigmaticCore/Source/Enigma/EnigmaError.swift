import Foundation

public enum EnigmaError: Error {
    case noContent
    case noPassword
    case noData
    case crypto(underlyingError: CFError)
    case cryptoUndefined
    case stringCreationFailed
}

extension EnigmaError {
    static func handle(unmanagedError: Unmanaged<CFError>?) -> EnigmaError {
        if let error = unmanagedError {
            return EnigmaError.crypto(underlyingError: error.takeUnretainedValue())
        } else {
            return EnigmaError.cryptoUndefined
        }
    }
}

extension EnigmaError: LocalizedError {
    
    public var errorDescription: String {
        switch self {
        case .noContent:
            return NSLocalizedString("No content to encrypt.", comment: "Needs comment")
        case .noPassword:
            return NSLocalizedString("No password provided.", comment: "Needs comment")
        case .noData:
            return NSLocalizedString("No data to decrypt.", comment: "Needs comment")
        case .crypto(_):
            return NSLocalizedString("Invalid credentials.", comment: "Needs comment")
        case .cryptoUndefined:
            return NSLocalizedString("Security Error.", comment: "Needs comment")
        case .stringCreationFailed:
            return NSLocalizedString("Data transformation error.", comment: "Needs comment")
        }
    }
    
    public var failureReason: String? {
        return NSLocalizedString("Enigma Error \(self.errorCode)", comment: "Needs comment")
    }
    
    public var recoverySuggestion: String? {
        switch self {
        case .noContent:
            return NSLocalizedString("Provide content to encrypt.", comment: "Needs comment")
        case .noPassword:
            return NSLocalizedString("Provide a password.", comment: "Needs comment")
        case .noData:
            return NSLocalizedString("Provide data to decrypt.", comment: "Needs comment")
        case let .crypto(underLyingError):
            if let recoverySuggestion = CFErrorCopyDescription(underLyingError) as String? {
                print(recoverySuggestion)
            }
            return NSLocalizedString("Please provide valid credentials.", comment: "Needs comment")
        case .cryptoUndefined:
            return NSLocalizedString("Unknown reason.", comment: "Needs comment")
        case .stringCreationFailed:
            return NSLocalizedString("String couldn't be constructed from decrypted data.", comment: "Needs comment")
        }
    }
}

extension EnigmaError: CustomNSError {
    
    public static var errorDomain: String {
        return "EnigmaErrorDomain"
    }
    
    public var errorCode: Int {
        switch self {
        case .noContent:
            return 1000
        case .noPassword:
            return 1001
        case .noData:
            return 1002
        case .crypto(_):
            return 2000
        case .cryptoUndefined:
            return 2001
        case .stringCreationFailed:
            return 3000
        }
    }
    
    public var errorUserInfo: [String : Any] {
        
        var errorUserInfo: [String : Any] = [
            NSLocalizedDescriptionKey: errorDescription
        ]
        
        if let failureReason = failureReason {
            errorUserInfo[NSLocalizedFailureReasonErrorKey] = failureReason
        }
        
        if let recoverySuggestion = recoverySuggestion {
            errorUserInfo[NSLocalizedRecoverySuggestionErrorKey] = recoverySuggestion
        }
        
        switch self {
        case .noContent:
            break
        case .noPassword:
            break
        case .noData:
            break
        case let .crypto(underLyingError):
            errorUserInfo[NSUnderlyingErrorKey] = underLyingError
        case .cryptoUndefined:
            break
        case .stringCreationFailed:
            break
        }
        
        return errorUserInfo
    }
}

