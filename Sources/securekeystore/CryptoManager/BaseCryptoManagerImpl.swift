import Security
import Foundation

class BaseCryptoManagerImpl: CryptoManagerProtocol {
    
    let keychainManager: KeychainManagerProtocol
    
    init(keychainManager: KeychainManagerProtocol) {
        self.keychainManager = keychainManager
    }
    
    func fetchPrivateKeyRef(tag: String, completion: @escaping (Bool, SecKey?, String?) -> Void) {
        keychainManager.retrieveKey(tag: tag) { key, resultMessage in
            if let privateKey = key {
                completion(true, privateKey, resultMessage)
            } else {
                print("Failed to retrieve private key with tag \(tag)")
                completion(false, nil, resultMessage)
            }
        }
    }
}
