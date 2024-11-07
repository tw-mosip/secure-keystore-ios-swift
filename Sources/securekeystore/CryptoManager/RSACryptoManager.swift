import Security
import Foundation
import CryptoKit

class RSACryptoManager: BaseCryptoManagerImpl {
    
    func sign(data: Data, withKeyTag keyTag: String, completion: @escaping (String?) -> Void) {
        fetchPrivateKeyRef(tag: keyTag) { success, privateKey, _ in
            guard success, let privateKey = privateKey else {
                completion(nil)
                return
            }
            
            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(privateKey, .rsaSignatureMessagePKCS1v15SHA256, data as CFData, &error) else {
                print("Error creating RSA signature: \(error!.takeRetainedValue().localizedDescription)")
                completion(nil)
                return
            }
            completion((signature as Data).base64EncodedString())
        }
        
        func verify(signature: String, originalData: Data, withKeyTag keyTag: String, completion: @escaping (Bool) -> Void) {
            fetchPrivateKeyRef(tag: keyTag) { success, publicKey, _ in
                guard success, let publicKey = SecKeyCopyPublicKey(publicKey!) else {
                    completion(false)
                    return
                }
                
                guard let signatureData = Data(base64Encoded: signature) else {
                    print("Invalid Base64 signature")
                    completion(false)
                    return
                }
                
                var error: Unmanaged<CFError>?
                let isVerified = SecKeyVerifySignature(publicKey,
                                                       .rsaSignatureMessagePKCS1v15SHA256,
                                                       originalData as CFData,
                                                       signatureData as CFData,
                                                       &error)
                
                if let error = error {
                    print("Error verifying RSA signature: \(error.takeRetainedValue().localizedDescription)")
                    completion(false)
                    return
                }
                
                completion(isVerified)
            }
        }
    }
}
