import LocalAuthentication
import Foundation

class BiometricsImpl: BiometricsProtocol {
    
    
    private static var popUpTitle: String = ""
    private static var popupDescription: String = ""

    
    private let authOffsetInSeconds: TimeInterval = 300
    
    // Thread-safe storage for last successful authentication time
    private var lastSuccessfulAuthTime: Date?
    private let authQueue = DispatchQueue(label: "biometrics.authQueue")
    
    // Queue to manage authentication requests
    private var isAuthenticating = false
    private var authenticationQueue = DispatchQueue(label: "biometrics.authenticationQueue", attributes: .concurrent)
    
    
    static func updatePopup(title: String, desc: String) {
        popUpTitle = title
        popupDescription = desc
    }
    
    
    func authenticateUser(reason: String, completion: @escaping (Bool, Error?) -> Void) {
        authenticationQueue.async(flags: .barrier) {
            self.performAuthentication(reason: reason, completion: completion)
        }
    }
    
    private func performAuthentication(reason: String, completion: @escaping (Bool, Error?) -> Void) {
        // Ensure that only one authentication is happening at a time
        while isAuthenticating {
            Thread.sleep(forTimeInterval: 0.1)
        }
        
        isAuthenticating = true
        guard isAuthenticationRequired() else {
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
                        self.updateLastSuccessfulAuth()
                        self.isAuthenticating = false
                        completion(true, nil)
                    } else if let authError = authError as! LAError?, authError.code == LAError.userFallback {
                        // Biometry is locked out after several failed attempts, fallback to password
                        self.fallbackToPassword(context: context, reason: reason, completion: completion)
                    } else {
                        self.isAuthenticating = false
                        completion(false, authError)
                    }
                }
            }
        } else {
            // Fallback to device password if biometrics are not available or disabled
            fallbackToPassword(context: context, reason: reason, completion: completion)
        }
    }

    private func fallbackToPassword(context: LAContext, reason: String, completion: @escaping (Bool, Error?) -> Void) {
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, authError in
            DispatchQueue.main.async {
                if success {
                    self.updateLastSuccessfulAuth()
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
    
    // Private method to check if authentication is required based on the delay
    private func isAuthenticationRequired() -> Bool {
        return authQueue.sync {
            guard let lastAuth = lastSuccessfulAuthTime else {
                return true // Require authentication if none has been recorded
            }
            
            return Date().timeIntervalSince(lastAuth) > authOffsetInSeconds
        }
    }
    
    // Private method to update the last successful authentication time
    private func updateLastSuccessfulAuth() {
        authQueue.sync {
            lastSuccessfulAuthTime = Date()
        }
    }
}
