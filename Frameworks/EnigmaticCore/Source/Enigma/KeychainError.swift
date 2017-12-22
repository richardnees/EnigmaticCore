import Foundation

public enum KeychainError: Error {
    case noPassword
    case unexpectedPasswordData
    case unhandledError(status: OSStatus)
}

extension KeychainError: LocalizedError {
    
    public var errorDescription: String {
        switch self {
        case .noPassword:
            return NSLocalizedString("No password provided.", comment: "Needs comment")
        case .unexpectedPasswordData:
            return NSLocalizedString("Unexpected password data.", comment: "Needs comment")
        case .unhandledError(_):
            return NSLocalizedString("Keychain error.", comment: "Needs comment")
        }
    }
    
    public var failureReason: String? {
        return NSLocalizedString("Enigma Keychain Error \(self.errorCode)", comment: "Needs comment")
    }
    
    public var recoverySuggestion: String? {
        switch self {
        case .noPassword:
            return NSLocalizedString("Provide a password.", comment: "Needs comment")
        case .unexpectedPasswordData:
            return NSLocalizedString("Data returned from keychain is malformed.", comment: "Needs comment")
        case let .unhandledError(status):
            return SecCopyErrorMessageString(status, nil) as String? ?? NSLocalizedString("Unknown Keychain error.", comment: "Needs comment")
        }
    }
}

extension KeychainError: CustomNSError {
    
    public static var errorDomain: String {
        return "EnigmaKeychainErrorDomain"
    }
    
    public var errorCode: Int {
        switch self {
        case .noPassword:
            return 1000
        case .unexpectedPasswordData:
            return 1001
        case .unhandledError(_):
            return 2000
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
        case .noPassword:
            break
        case .unexpectedPasswordData:
            break
        case .unhandledError(_):
            errorUserInfo[NSUnderlyingErrorKey] = recoverySuggestion
        }
        
        return errorUserInfo
    }
}
