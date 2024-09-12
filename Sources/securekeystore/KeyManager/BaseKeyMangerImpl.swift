import Security
import Foundation

class BaseKeyManagerImpl: KeyManagerProtocol {  // make file name basekeymanagerimpl
    
    var keyType: KeyType {
        fatalError("This property must be overridden")
    }
    
    private let biometricManager: BiometricsProtocol
    
    init(biometricManager: BiometricsProtocol = BiometricsImpl()) {
        self.biometricManager = biometricManager
    }
    
    func generateKeyPair(tag: String, completion: @escaping (Bool, SecKey?, SecKey?) -> Void) {
        authenticateUser { success in
            if !success {
                completion(false, nil, nil)
                return
            }
            
            let parameters: [String: Any] = [
                kSecAttrKeyType as String: self.keyType.secAttrKeyType,
                kSecAttrKeySizeInBits as String: self.keyType.keySize,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrIsPermanent as String: true,
                    kSecAttrApplicationTag as String: tag
                ]
            ]
            
            var publicKey, privateKey: SecKey?
            let status = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)
            guard status == errSecSuccess else {
                completion(false, nil, nil)
                return
            }
        
            completion(true, privateKey, publicKey)
    
        }
    }
    
    func deleteKeyPair(tag: String, completion: @escaping (Bool) -> Void) {
        authenticateUser { success in
             if !success  {
                completion(false)
                return
            }
            
            let privateKeyTag = "\(tag).private"
            let publicKeyTag = "\(tag).public"
            
            let deletePrivateKey = self.deleteKey(tag: privateKeyTag)
            let deletePublicKey = self.deleteKey(tag: publicKeyTag)
            
            completion(deletePrivateKey && deletePublicKey)
        }
    }
    
    private func deleteKey(tag: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }
    
    func rotateKeyPair(tag: String, completion: @escaping (Bool, SecKey?, SecKey?) -> Void) {
        deleteKeyPair(tag: tag) { success in
            guard success else {
                completion(false, nil, nil)
                return
            }
            
            self.generateKeyPair(tag: tag) { success, privateKey, publicKey in
                completion(success, privateKey, publicKey)
            }
        }
    }
    
     func  authenticateUser(completion: @escaping (Bool) -> Void) {
         biometricManager.authenticateUser(keyType:"",reason: "Authenticate to access your keys") { success, error in
            if let error = error {
                print("Biometric authentication failed: \(error.localizedDescription)")
            }
            completion(success)
        }
    }
}
