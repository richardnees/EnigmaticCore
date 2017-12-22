import Foundation

public class EnigmaKeychainSavePasswordOperation: EnigmaKeychainPasswordOperation {
    public override func main() {
        guard let data = data else {
            error = EnigmaError.noData
            return
        }

        guard
            let password = password,
            password.isEmpty == false
            else {
            error = KeychainError.noPassword
            return
        }
        
        guard let passwordData = password.data(using: .utf8) else {
            error = KeychainError.unexpectedPasswordData
            return
        }

        let account = String(data.hashValue)
        
        var query = defaultQuery
        query[kSecAttrAccount] = account
        query[kSecValueData] = passwordData
        
        let status = SecItemAdd(query as CFDictionary, nil)
        
        guard
            status == errSecSuccess ||
            status == errSecUserCanceled
            else {
                error = KeychainError.unhandledError(status: status)
                return
        }
    }
}
