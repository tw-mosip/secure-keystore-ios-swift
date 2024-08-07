import Security
import Foundation

class RSAKeyManager: BaseKeyManagerImpl {
    override var keyType: KeyType {
        return .rsa2048
    }
}
