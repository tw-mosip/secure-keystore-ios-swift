import LocalAuthentication

public protocol BiometricsProtocol {
    func authenticateUser(reason: String, completion: @escaping (Bool, Error?) -> Void)
    func hasBiometricsEnabled()->Bool
}
