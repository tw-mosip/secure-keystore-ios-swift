import Security
import Foundation

class AESKeyManager: BaseKeyManagerImpl {
    override var keyType: KeyType {
        return .aes
    }
    
    override func generateKeyPair(tag: String, completion: @escaping (Bool, SecKey?, SecKey?) -> Void) {
        authenticateUser { success in
            guard success else {
                completion(false, nil, nil)
                return
            }
            print("why again?")
            
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: self.keyType.secAttrKeyType as Any,
                kSecAttrKeySizeInBits as String: self.keyType.keySize,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
                ]
            ]
            
            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                print("Error creating key: \(error!.takeRetainedValue() as Error)")
                completion(false,nil,nil)
                return
            }
            
            completion(true,privateKey,SecKeyCopyPublicKey(privateKey))
        }
    }
    
}

