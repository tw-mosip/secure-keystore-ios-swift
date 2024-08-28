import Security
import Foundation

protocol KeychainManagerProtocol {
    func storeKey(key: SecKey, tag: String,completion: @escaping (Bool) -> Void)
    func retrieveKey(tag: String,completion: @escaping (SecKey?) -> Void)
    func deleteKey(tag: String,completion: @escaping (Bool) -> Void)
    func storeGenericKey(data: Data?, account: String,completion: @escaping (Bool) -> Void)
    func retrieveGenericKey(account: String, completion: @escaping (Data?) -> Void)
    func keyExists(tag: String, completion: @escaping (Bool) -> Void)
    func clearKeys(completion: @escaping (Bool) -> Void)
}

