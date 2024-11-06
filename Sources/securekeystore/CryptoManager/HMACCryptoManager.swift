import Foundation
import Security
import CryptoKit

class HMACCryptoManager:BaseCryptoManagerImpl{
    
    @available(iOS 13.0, *)
    func generateHmacSha(tag: String, message: String, completion: @escaping (String?)->Void){
        keychainManager.retrieveGenericKey(account: tag){
            data, _ in if(data == nil){
                completion(nil)
            }
            else
            {
                let key=SymmetricKey(data: data!)
                let hmac = HMAC<SHA256>.authenticationCode(for:Data(message.utf8), using: key)
                let hmacHexString = hmac.map { String(format: "%02hhx", $0) }.joined()
                completion(hmacHexString)
            }
        }
    }
}


