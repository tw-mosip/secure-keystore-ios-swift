import Foundation
import Security

public protocol SecureKeystoreProtocol {
    
    func generateKeyPair(type: String, tag: String, isAuthRequired: Bool, authTimeout: Int32, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)
    
    func deleteKeyPair(tag: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)
    
    func hasAlias(tag: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)
    
    func sign(signAlgorithm: String, alias: String, data: String, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)
    
    func storeGenericKey(publicKey: String, privateKey: String, account: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)
    
    func retrieveGenericKey(account: String, onSuccess: @escaping (String?, String?) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)
    
    func hasBiometricsEnabled() -> Bool
    
    func updatePopup(title: String, desc: String)
    
    func generateKey(alias: String, authRequired: Bool, authTimeout: Int32, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)
    
    func encryptData(alias: String, data: String, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)
    
    func decryptData(alias: String, data: String, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)
    
    @available(iOS 13.0, *)
    func generateHmacshaKey(alias: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)
    
    @available(iOS 13.0, *)
    func generateHmacSha(alias: String, data: String, onSuccess: @escaping (String?) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)
    
    func clearKeys(onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)
    
    func retrieveKey(tag: String, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void)
    
    // iCloud Key-Value Storage Methods
    func storeValueInCloud(key: String, value: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)
    
    func retrieveValueFromCloud(key: String, onSuccess: @escaping (String?) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)
    
    func removeValueFromCloud(key: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)
}
