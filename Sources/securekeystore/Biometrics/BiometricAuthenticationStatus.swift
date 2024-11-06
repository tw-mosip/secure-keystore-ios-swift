enum BiometricAuthentication {
    case success
    case failed
    
    var status: Bool {
        switch self {
        case .success:
            return true
        case .failed:
            return false
        }
    }
    
    var statusMessage: String {
        switch self {
        case .success:
            return "Biometric authentication success"
        case .failed:
            return "User has cancelled biometric"
        }
    }
}
