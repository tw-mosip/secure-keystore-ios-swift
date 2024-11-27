import Foundation

protocol iCloudStorageProtocol {
    func setItem(key: String, value: String)
    func getItem(key: String) -> String?
    func removeItem(key: String)
}
