import Security

enum KeyType {
    case rsa2048
    case ecr1
    case aes
    case hmac
    
    var secAttrKeyType: CFString? {
        switch self {
        case .rsa2048:
            return kSecAttrKeyTypeRSA
        case .ecr1:
            return kSecAttrKeyTypeECSECPrimeRandom
        case .aes:
           return kSecAttrKeyTypeECSECPrimeRandom
        case .hmac:
            return nil
        }
    }
    
    var keySize: Int {
        switch self {
        case .rsa2048:
            return 2048
        case .ecr1:
            return 256
        case .aes:
            return 256
        case .hmac:
            return 256
           
        }
    }
}
