import Foundation
import Security

public class EnigmaKeychainMatchPasswordOperation: EnigmaKeychainPasswordOperation {
    public override func main() {
        guard let data = data else {
            error = EnigmaError.noData
            return
        }

        var query = defaultQuery

        if account == nil {
            account = String(data.hashValue)
        }

        query[kSecAttrAccount] = account
        query[kSecReturnData] = true
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard
            status == errSecSuccess ||
            status == errSecUserCanceled
            else {
                error = KeychainError.unhandledError(status: status)
                return
        }
        
        guard
            let passwordData = result as? Data,
            let passwordMatch = String(data: passwordData, encoding: .utf8)
            else {
                error = KeychainError.unexpectedPasswordData
                return
        }
        
        password = passwordMatch
    }
}
