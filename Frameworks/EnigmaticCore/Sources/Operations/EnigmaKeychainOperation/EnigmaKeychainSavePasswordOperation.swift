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

        var query = defaultQuery

        if account == nil {
            account = String(data.hashValue)
        }
        query[kSecAttrAccount] = account
        
        let attributes = [kSecValueData:passwordData]
        
        var status: OSStatus?
        
        status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)

        if status == errSecItemNotFound {
            query[kSecValueData] = passwordData
            
            var result: AnyObject?
            status = SecItemAdd(query as CFDictionary, &result)
            
            guard
                status == errSecSuccess ||
                status == errSecUserCanceled
                else {
                    if let status = status {
                        error = KeychainError.unhandledError(status: status)
                    }
                    return
            }
        }
    }
}
