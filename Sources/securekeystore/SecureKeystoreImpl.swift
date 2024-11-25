import Foundation
import Security

@available(iOS 13.0, *)
public class SecureKeystoreImpl:SecureKeystoreProtocol {
    
    private let keychainManager: KeychainManagerProtocol
    private let rsaCryptoManager: RSACryptoManager
    private let ecr1CryptoManager: ECR1CryptoManager
    private let aesCryptoManager: AESCryptoManager
    private let aesKeyManager: AESKeyManager
    private let biometrics: BiometricsProtocol
    
    public init() {
        self.biometrics=BiometricsImpl()
        self.keychainManager = KeychainManagerImpl(biometrics: biometrics)
        self.rsaCryptoManager = RSACryptoManager(keychainManager: keychainManager)
        self.ecr1CryptoManager = ECR1CryptoManager(keychainManager: keychainManager)
        self.aesKeyManager=AESKeyManager()
        self.aesCryptoManager=AESCryptoManager(keychainManager: keychainManager)
    }
    
    internal init(keychainManager: KeychainManagerProtocol,
                  rsaCryptoManager: RSACryptoManager,
                  ecr1CryptoManager: ECR1CryptoManager) {
        self.keychainManager = keychainManager
        self.rsaCryptoManager = rsaCryptoManager
        self.ecr1CryptoManager = ecr1CryptoManager
        self.biometrics=BiometricsImpl()
        self.aesKeyManager=AESKeyManager()
        self.aesCryptoManager=AESCryptoManager(keychainManager: keychainManager)
    }
    
    public func generateKeyPair(type: String, tag: String, isAuthRequired:Bool, authTimeout:Int32, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void) {
        if type == "RSA" {
            let rsaKeyManager = RSAKeyManager()
            rsaKeyManager.generateKeyPair(tag: tag) { success, privateKey, publicKey in
                if success {
                    self.keychainManager.storeKey(key: privateKey!, tag: tag) { success in
                        setAuthTimeOutForKey(keyType: type, authTimeout:isAuthRequired == true ? TimeInterval(authTimeout):TimeInterval(Int.max))
                        onSuccess((publicKey!.toPKCS8PublicKeyString())!)
                    }
                } else {
                    onFailure("","Key storing error")
                }
            }
        } else if type == "ECR1" {
            let ecr1KeyManager = ECR1KeyManager()
            ecr1KeyManager.generateKeyPair(tag: tag) { success, privateKey, publicKey in
                if success {
                    self.keychainManager.storeKey(key: privateKey!, tag: tag) { success in
                        setAuthTimeOutForKey(keyType: type, authTimeout:isAuthRequired == true ? TimeInterval(authTimeout):TimeInterval(Int.max))
                        onSuccess((publicKey?.toPKCS8PublicKeyString())!)
                    }
                } else {
                    onFailure("","Key storing error")
                }
            }
        } else {
            onFailure("","Key generation error")
        }
    }
    
    public func deleteKeyPair(tag: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void) {
        keychainManager.deleteKey(tag: tag) { resultMessage in
            if resultMessage == "Key deleted successfully" {
                onSuccess(true)
            } else {
                onFailure("", resultMessage)
            }
        }
    }
    
    public func hasAlias(tag: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void) {
        keychainManager.keyExists(tag: tag) { exists in
            exists == true ? onSuccess(exists) : onFailure("","Key does not exists")
        }
    }
    
    @available(iOS 13.0, *)
    public func sign(signAlgorithm: String, alias: String, data: String, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void) {
        guard let messageData = data.data(using: .ascii) else {
            onFailure("","Message conversion failed")
            return
        }
        
        if signAlgorithm == "RSA" {
            rsaCryptoManager.sign(data: messageData, withKeyTag: alias){
                sign in
                (sign != nil) ? onSuccess(sign!) : onFailure("","RSA signing failed")
            }
        } else if signAlgorithm == "ECR1" {
            ecr1CryptoManager.sign(data: messageData, withKeyTag: alias){
                sign in
                (sign != nil) ? onSuccess(sign!) : onFailure("","EC signing failed")
            }
        } else {
            onFailure("","Invalid key type")
        }
        
    }
    
    public func retrieveKey(tag: String, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void){
        keychainManager.retrieveKey(tag: tag){ key, resultMessage in
            key != nil ? onSuccess(key!.toPKCS8PublicKeyString()!) : onFailure("", resultMessage)
        }
    }
    
    public func storeGenericKey(publicKey: String, privateKey: String, account: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping (_ code: String, _ message: String) -> Void) {
        let keyPair = ["privateKey": privateKey, "publicKey": publicKey]
        let signingKeysWithTimeOut: [String] = ["ES256K", "ED25519", "RS256", "ES256"]
        
        do {
            let serializedKeyPair = try NSKeyedArchiver.archivedData(withRootObject: keyPair, requiringSecureCoding: false)
            keychainManager.storeGenericKey(data: serializedKeyPair, account: account) { success in
                let timeout: TimeInterval = signingKeysWithTimeOut.contains(account) ? TimeInterval(0) : TimeInterval(-1)
                setAuthTimeOutForKey(keyType: account, authTimeout: timeout)
                success ? onSuccess(true) : onFailure("STORE_ERROR", "Key storing failed")
            }
        } catch {
            onFailure("SERIALIZATION_ERROR", "Failed to serialize key pair")
        }
    }
    
    public func retrieveGenericKey(account: String, onSuccess: @escaping (String?,String?) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void) {
        keychainManager.retrieveGenericKey(account: account) { data, resultMessage in
            if let data = data {
                do {
                    if let keyPair = try NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(data) as? [String: String?],
                       let privateKey = keyPair["privateKey"],
                       let publicKey = keyPair["publicKey"]{
                        onSuccess(privateKey, publicKey)
                    } else {
                        onFailure("DESERIALIZATION_ERROR", "Failed to deserialize key pair")
                    }
                } catch {
                    onFailure("DESERIALIZATION_ERROR", "Failed to deserialize key pair")
                }
            } else {
                let errorMessage = (resultMessage?.isEmpty == true) ? "Key retrieving error" : resultMessage!
                onFailure("", errorMessage)
            }
        }
    }
    
    public func hasBiometricsEnabled()->Bool{
        return biometrics.hasBiometricsEnabled()
    }
    
    public func updatePopup(title:String, desc:String){
        BiometricsImpl.updatePopup(title: title, desc:desc)
    }
    
    public func generateKey(alias: String, authRequired:Bool, authTimeout:Int32, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void){
        
        keychainManager.keyExists(tag: alias) { exists in
            if exists {
                // If the key exists, return success immediately
                onSuccess(true)
            } else {
                // If the key does not exist, generate a new one
                self.aesKeyManager.generateKeyPair(tag: alias) { success, privateKey, publicKey in
                    if success {
                        setAuthTimeOutForKey(keyType: alias, authTimeout:authRequired == true ? TimeInterval(authTimeout):TimeInterval(-1))
                        // Store the new key in the keychain
                        self.keychainManager.storeKey(key: privateKey!, tag: alias) { storeSuccess in
                            storeSuccess ? onSuccess(true) : onFailure("KEY_STORE_ERROR", "Failed to store AES key")
                        }
                    } else {
                        onFailure("KEY_GENERATION_ERROR", "Failed to generate AES key")
                    }
                }
            }
        }
    }
    
    public func encryptData(alias:String, data:String, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void)
    {
        aesCryptoManager.encrypt(keyTag: alias, data: data){ result in
            if let encryptedData = result, encryptedData != BiometricAuthentication.failed.statusMessage {
                onSuccess(encryptedData)
            }
            else{
                onFailure("", "Encryption failed: \(result!)")
            }
        }
    }
    
    public func decryptData(alias:String, data:String, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void)
    {
        aesCryptoManager.decrypt(keyTag: alias, data: data){ result in
            if let decryptedText = result, decryptedText != BiometricAuthentication.failed.statusMessage {
                onSuccess(decryptedText)
            } else {
                onFailure("", "Decryption failed: \(result!)")
            }
        }
    }
    
    @available(iOS 13.0, *)
    public func generateHmacshaKey(alias:String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void){
        let hmacKeyManager: ()=HMACKeyManager().generateHmacshaKey(tag: alias){ success, key in
            if(!success){
                onFailure("", "HMAC key generation failed")
            }
            else{
                let data=key?.withUnsafeBytes { Data($0) }
                setAuthTimeOutForKey(keyType: alias, authTimeout:TimeInterval(-1))
                self.keychainManager.storeGenericKey(data:data , account: alias){
                    success in
                    if(success){
                        onSuccess(true)
                    }
                    else {
                        onFailure("","Key storing error")
                    }
                    
                }
            }
        }
    }
    
    @available(iOS 13.0, *)
    public func generateHmacSha(alias: String, data: String, onSuccess: @escaping (String?) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void){
        let hmac: ()=HMACCryptoManager(keychainManager: keychainManager).generateHmacSha(tag: alias, message: data){
            hash in
            if(hash != nil){
                onSuccess(hash)
            }
            else{
                onFailure("", "hash generation failed")
            }
        }
    }
    
    public func clearKeys(onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void) -> Void {
        keychainManager.clearKeys(){
            success in if(success){
                onSuccess(success)
            }
            else{
                onFailure("", "key deletion failed")
            }
        }
    }
}
