import Security
import Foundation
import CryptoKit

class HMACKeyManager: BaseKeyManagerImpl {
    override var keyType: KeyType {
        return .hmac
    }
    
    override func generateKeyPair(tag: String, completion: @escaping (Bool, SecKey?, SecKey?) -> Void) {
        return
    }
    
    @available(iOS 13.0, *)
    func generateHmacshaKey(tag:String, completion:@escaping(Bool, SymmetricKey?)->Void){
            let hmacKey=SymmetricKey(size: .bits256)
            completion(true,hmacKey)
        }
        
    }
