import Security
import Foundation

class ECR1CryptoManager: BaseCryptoManagerImpl {
    
    
    func sign(data: Data, withKeyTag keyTag: String, completion: @escaping (String?) -> Void) {
        fetchPrivateKeyRef(tag: keyTag) { success, privateKey in
            guard success, let privateKey = privateKey else {
                completion(nil)
                return
            }
            
            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA1, data as CFData, &error) else {
                print("Error creating ECR1 signature: \(error!.takeRetainedValue().localizedDescription)")
                completion(nil)
                return
            }
            
            let derSignature = signature as Data
            completion( Data(signature as Data).base64URLEncodedString())
        
        }
    }
}



