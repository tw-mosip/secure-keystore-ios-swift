import Security

protocol KeyManagerProtocol {
    var keyType: KeyType { get }
    func generateKeyPair(tag: String, completion: @escaping (Bool, SecKey?, SecKey?) -> Void)
    func deleteKeyPair(tag: String, completion: @escaping (Bool) -> Void)
    func rotateKeyPair(tag: String, completion: @escaping (Bool, SecKey?, SecKey?) -> Void)
}
