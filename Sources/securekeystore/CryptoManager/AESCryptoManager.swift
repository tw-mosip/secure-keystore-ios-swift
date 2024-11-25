import Foundation

class AESCryptoManager:BaseCryptoManagerImpl{
    
    func encrypt(keyTag:String,data: String, completion: @escaping (String?)->Void){
        fetchPrivateKeyRef(tag: keyTag) { success, privateKey, resultMessage  in
            guard success, let privateKey = privateKey else {
                completion(resultMessage)
                return
            }
            
            let publicKey=SecKeyCopyPublicKey(privateKey)
            var error: Unmanaged<CFError>?
            guard let encryptedData = SecKeyCreateEncryptedData(
                publicKey!,
                .eciesEncryptionCofactorVariableIVX963SHA256AESGCM,
                data.data(using: .utf8)! as CFData,
                &error
            ) else {
                print("Error encrypting data: \(error!.takeRetainedValue() as Error)")
                completion(resultMessage)
                return
               }
            completion((encryptedData as Data).base64EncodedString())
        }
    }
    
    func decrypt(keyTag:String,data: String, completion: @escaping (String?)->Void){
        fetchPrivateKeyRef(tag: keyTag) { success, privateKey, resultMessage in
            guard let privateKey = privateKey else {
                completion(resultMessage)
                return
            }
            let cipherData=Data(base64Encoded: data)
            var error: Unmanaged<CFError>?
            guard let decryptedData = SecKeyCreateDecryptedData(
                privateKey,
                .eciesEncryptionCofactorVariableIVX963SHA256AESGCM,
                cipherData! as CFData,
                &error
            ) else {
                print("Error decrypting data: \(error!.takeRetainedValue() as Error)")
                completion(resultMessage)
                return
               }
            
            completion(String(data: decryptedData as Data,encoding: .utf8))
        }
    }
}
