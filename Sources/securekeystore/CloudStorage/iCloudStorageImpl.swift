import Foundation

class iCloudStorageImpl: iCloudStorageProtocol {
    
    private let iCloudStore = NSUbiquitousKeyValueStore.default

    func setItem(key: String, value: String) {
        iCloudStore.set(value, forKey: key)
        iCloudStore.synchronize()
    }

    func getItem(key: String) -> String? {
        return iCloudStore.string(forKey: key)
    }

    func removeItem(key: String) {
        iCloudStore.removeObject(forKey: key)
        iCloudStore.synchronize()
    }
}
