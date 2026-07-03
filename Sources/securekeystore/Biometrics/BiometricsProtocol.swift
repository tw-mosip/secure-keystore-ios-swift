import LocalAuthentication

public protocol BiometricsProtocol {
    func authenticateUser(keyType: String, reason: String, completion: @escaping (Bool, Error?) -> Void)
    func hasBiometricsEnabled()->Bool
}
