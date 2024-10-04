import Foundation

private var keyAuthTimeouts: [String: TimeInterval] = [:]

func getAuthTimeOutForKeyType(keyType: String) -> TimeInterval {
    
    if !keyAuthTimeouts.isEmpty {
        return keyAuthTimeouts[keyType] ?? -1
    }

    
    let semaphore = DispatchSemaphore(value: 0)
    var timeout: TimeInterval = -1
    keyAuthTimeouts["keyAuthMap"]=TimeInterval(-1)
    KeychainManagerImpl(biometrics: BiometricsImpl()).retrieveGenericKey(account: "keyAuthMap") { data in
        let storedData: Data = data ?? "".data(using: .utf8)!
        let storedString: String = String(data: storedData, encoding: .utf8) ?? ""
        
        if let storedMap = deserializeTimeouts(storedString) {
            keyAuthTimeouts = storedMap
        }
        
        timeout = keyAuthTimeouts[keyType] ?? -1
        semaphore.signal()
    }

    semaphore.wait()

    return timeout
}

func setAuthTimeOutForKey(keyType: String, authTimeout: TimeInterval) -> Bool {
    
    keyAuthTimeouts[keyType] = authTimeout
    
    guard let serializedTimeouts = serializeTimeouts(keyAuthTimeouts),
          let dataToStore = serializedTimeouts.data(using: .utf8) else {
        
        print("Failed to serialize auth timeouts.")
        return false
    }
    
    let semaphore = DispatchSemaphore(value: 0)
    var success = false
    
    
    KeychainManagerImpl(biometrics: BiometricsImpl()).storeGenericKey(data: dataToStore, account: "keyAuthMap") { result in
        success = result
        semaphore.signal()
    }
    
    _ = semaphore.wait(timeout: .distantFuture)
    
    if success {
        print("Auth timeout for \(keyType) successfully stored.")
    } else {
        print("Failed to store auth timeout for \(keyType).")
    }
    
    return success
}

private func deserializeTimeouts(_ serializedString: String) -> [String: TimeInterval]? {
    guard let data = serializedString.data(using: .utf8),
          let jsonObject = try? JSONSerialization.jsonObject(with: data, options: []),
          let timeoutMap = jsonObject as? [String: TimeInterval] else {
        return nil
    }
    return timeoutMap
}

private func serializeTimeouts(_ timeouts: [String: TimeInterval]) -> String? {
    guard let jsonData = try? JSONSerialization.data(withJSONObject: timeouts, options: []) else {
        return nil
    }
    return String(data: jsonData, encoding: .utf8)
}
