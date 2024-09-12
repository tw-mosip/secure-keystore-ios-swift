import Security
import Foundation

class KeychainManagerImpl: KeychainManagerProtocol {
    
    private let biometrics: BiometricsProtocol
    private let keychainQueue = DispatchQueue(label: "keychainQueue")
    
    init(biometrics: BiometricsProtocol) {
        self.biometrics = biometrics
    }
    
    private func authenticateUser(keyType:String, completion: @escaping (Bool) -> Void) {
        biometrics.authenticateUser(keyType:keyType,reason: "Authenticate to access your keys") { success, error in
            if let error = error {
                print("Biometric authentication failed: \(error.localizedDescription)")
            }
            completion(success)
        }
    }
    
    func storeKey(key: SecKey, tag: String, completion: @escaping (Bool) -> Void) {
        keychainQueue.async {
            
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrLabel as String: tag+"label",
                kSecAttrApplicationTag as String: tag,
                kSecValueRef as String: key
            ]
            
            let status = SecItemAdd(query as NSDictionary, nil)
            completion(status == errSecSuccess)
        }
        
    }
    func dumpAllSecKeys() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as NSDictionary, &result)
        
        guard status == errSecSuccess else {
            print("Failed to retrieve keys from keychain: \(status)")
            return
        }
    }
    
    func retrieveKey(tag: String, completion: @escaping (SecKey?) -> Void) {
        keychainQueue.async {
            self.authenticateUser(keyType:tag) { success in
                guard success else {
                    completion(nil)
                    return
                }
                self.dumpAllSecKeys()
                let query: [String: Any] = [
                    kSecClass as String: kSecClassKey,
                    kSecAttrApplicationTag as String: tag,
                    kSecAttrLabel as String: tag+"label",
                    kSecReturnRef as String: true,
                    kSecMatchLimit as String: kSecMatchLimitOne
                ]
                
                var item: CFTypeRef?
                let status = SecItemCopyMatching(query as NSDictionary, &item)
                
                guard status == errSecSuccess else {
                    completion(nil)
                    return
                }
                let key = item as! SecKey
                completion(key)
            }
        }
    }
    
    func deleteKey(tag: String, completion: @escaping (Bool) -> Void) {
        keychainQueue.async {
            self.authenticateUser(keyType:tag) { success in
                guard success else {
                    completion(false)
                    return
                }
                
                let query: [String: Any] = [
                    kSecClass as String: kSecClassKey,
                    kSecAttrApplicationTag as String: tag
                ]
                
                let status = SecItemDelete(query as CFDictionary)
                completion(status == errSecSuccess)
            }
        }
    }
    
    func storeGenericKey(data: Data?, account: String, completion: @escaping (Bool) -> Void) {
        keychainQueue.async {
            
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: account,
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ]
            
            // Remove any existing item with the same account
            SecItemDelete(query as CFDictionary)
            
            let status = SecItemAdd(query as CFDictionary, nil)
            completion(status == errSecSuccess)
            
        }
    }
    
    func retrieveGenericKey(account: String, completion: @escaping (Data?) -> Void) {
        keychainQueue.async {
            self.authenticateUser(keyType:account) { success in
                guard success else {
                    completion(nil)
                    return
                }
                
                let query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: account,
                    kSecReturnData as String: kCFBooleanTrue!,
                    kSecMatchLimit as String: kSecMatchLimitOne
                ]
                
                var item: CFTypeRef?
                let status = SecItemCopyMatching(query as CFDictionary, &item)
                
                guard status == errSecSuccess, let data = item as? Data else {
                    completion(nil)
                    return
                }
                completion(data)
            }
        }
    }
    
    func keyExists(tag: String, completion: @escaping (Bool) -> Void) {
        keychainQueue.async {
            let queryEnclaveKeys: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecReturnAttributes as String: kCFBooleanTrue!
            ]
            
            let queryGenericKey: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: tag,
                kSecReturnData as String: kCFBooleanTrue!,
                kSecMatchLimit as String: kSecMatchLimitOne
            ]
            
            var item: CFTypeRef?
            let statusForEnclaveKeys = SecItemCopyMatching(queryEnclaveKeys as CFDictionary, &item)
            let statusForGenericKeys = SecItemCopyMatching(queryGenericKey as CFDictionary, &item)
            completion(statusForEnclaveKeys == errSecSuccess || statusForGenericKeys == errSecSuccess)
        }
    }
    
    
    func clearKeys(completion: @escaping (Bool) -> Void) {
        keychainQueue.async {
            var success = true
            
            let classes = [kSecClassGenericPassword, kSecClassKey]
            
            for secClass in classes {
                let query: [String: Any] = [
                    kSecClass as String: secClass
                ]
                
                let status = SecItemDelete(query as CFDictionary)
                if status != errSecSuccess && status != errSecItemNotFound {
                    success = false
                    break
                }
            }
            
            completion(success)
        }
        
    }
}
