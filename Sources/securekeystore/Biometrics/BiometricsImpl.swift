import LocalAuthentication
import Foundation

class BiometricsImpl: BiometricsProtocol {
    
    private static var popUpTitle: String = ""
    private static var popupDescription: String = ""
    
    // Thread-safe storage for last successful authentication time per key type
    private var lastSuccessfulAuthTime: [String: Date] = [:]
    private let authQueue = DispatchQueue(label: "biometrics.authQueue")
    
    // Queue to manage authentication requests
    private var isAuthenticating = false
    private var authenticationQueue = DispatchQueue(label: "biometrics.authenticationQueue", attributes: .concurrent)
    
    static func updatePopup(title: String, desc: String) {
        popUpTitle = title
        popupDescription = desc
    }
    
    func authenticateUser(keyType: String, reason: String, completion: @escaping (Bool, Error?) -> Void) {
        authenticationQueue.async(flags: .barrier) {
            self.performAuthentication(keyType: keyType, reason: reason, completion: completion)
        }
    }
    
    private func performAuthentication(keyType: String, reason: String, completion: @escaping (Bool, Error?) -> Void) {
        // Ensure that only one authentication is happening at a time
        while isAuthenticating {
            Thread.sleep(forTimeInterval: 0.1)
        }
        
        isAuthenticating = true
        let isAuthRequired=isAuthenticationRequired(forKeyType: keyType)
        if(!isAuthRequired)
        {
            DispatchQueue.main.async {
                completion(true, nil)
            }
            isAuthenticating = false
            return
        }
        
        let context = LAContext()
        var error: NSError?
        
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, authError in
                DispatchQueue.main.async {
                    if success {
                        self.updateLastSuccessfulAuth(forKeyType: keyType)
                        self.isAuthenticating = false
                        completion(true, nil)
                    } else if let authError = authError as! LAError?, authError.code == LAError.userFallback {
                        // Biometry is locked out after several failed attempts, fallback to password
                        self.fallbackToPassword(context: context, reason: reason, keyType: keyType, completion: completion)
                    } else {
                        self.isAuthenticating = false
                        completion(false, authError)
                    }
                }
            }
        } else {
            // Fallback to device password if biometrics are not available or disabled
            fallbackToPassword(context: context, reason: reason, keyType: keyType, completion: completion)
        }
    }
    
    private func fallbackToPassword(context: LAContext, reason: String, keyType: String, completion: @escaping (Bool, Error?) -> Void) {
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, authError in
            DispatchQueue.main.async {
                if success {
                    self.updateLastSuccessfulAuth(forKeyType: keyType)
                }
                self.isAuthenticating = false
                completion(success, authError)
            }
        }
    }
    
    // Method to check if biometrics are enabled
    func hasBiometricsEnabled() -> Bool {
        let context = LAContext()
        var error: NSError?
        
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }
    
    // Private method to check if authentication is required based on the key type and its timeout
    private func isAuthenticationRequired(forKeyType keyType: String) -> Bool {
        return authQueue.sync {
            let authTimeOutForKeyType: TimeInterval = getAuthTimeOutForKeyType(keyType: keyType)
            guard let lastAuth: Date = self.lastSuccessfulAuthTime[keyType] else {
                if(authTimeOutForKeyType > -1)
                {
                    return true
                }
                return false
            }
            let timeout = authTimeOutForKeyType
            return Date().timeIntervalSince(lastAuth) > timeout
        }
    }
    
    // Private method to update the last successful authentication time for the specific key type
    private func updateLastSuccessfulAuth(forKeyType keyType: String) {
        authQueue.sync {
            lastSuccessfulAuthTime[keyType] = Date()
        }
    }

}
