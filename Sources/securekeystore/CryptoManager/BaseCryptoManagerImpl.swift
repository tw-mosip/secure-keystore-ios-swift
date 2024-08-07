import Security
import Foundation

class BaseCryptoManagerImpl: CryptoManagerProtocol {
    
    let keychainManager: KeychainManagerProtocol
    
    init(keychainManager: KeychainManagerProtocol) {
        self.keychainManager = keychainManager
    }
    
    func fetchPrivateKeyRef(tag: String, completion: @escaping (Bool, SecKey?) -> Void) {
        keychainManager.retrieveKey(tag: tag) { key in
            if let privateKey = key {
                completion(true, privateKey)
            } else {
                print("Failed to retrieve private key with tag \(tag)")
                completion(false, nil)
            }
        }
    }
}
