import Foundation
import Security

extension SecKey {
    public func toPEMString() -> String? {
        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(self, &error) as Data? else {
            print("Error converting key to data: \(error!.takeRetainedValue().localizedDescription)")
            return nil
        }
        
        let base64Key = keyData.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        let keyType = self.secKeyTypeString()
        
        return """
        -----BEGIN \(keyType) KEY-----
        \(base64Key)
        -----END \(keyType) KEY-----
        """
    }
    
    private func secKeyTypeString() -> String {
        let attributes = SecKeyCopyAttributes(self)! as NSDictionary
        let keyType = attributes[kSecAttrKeyType as String] as! CFString
        
        if keyType == kSecAttrKeyTypeRSA {
            return "RSA PUBLIC"
        } else if keyType == kSecAttrKeyTypeECSECPrimeRandom {
            return "EC PUBLIC"
        } else {
            return "UNKNOWN"
        }
    }
    
    public func toJWK() -> String? {
        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(self, &error) as Data? else {
            print("Error converting key to data: \(error!.takeRetainedValue().localizedDescription)")
            return nil
        }

        let attributes = SecKeyCopyAttributes(self)! as NSDictionary
        let keyType = attributes[kSecAttrKeyType as String] as! CFString

        if keyType == kSecAttrKeyTypeRSA {
            return self.rsaPublicKeyToJWKJson(keyData: keyData)
        } else if keyType == kSecAttrKeyTypeECSECPrimeRandom {
            // Handle EC keys here if needed
            return nil
        } else {
            print("Unsupported key type")
            return nil
        }
    }

    private func rsaPublicKeyToJWKJson(keyData: Data) -> String? {
        guard keyData.count > 8 else { return nil }

        let modulusLength = Int(keyData[7])
        let exponentIndex = 9 + modulusLength
        let exponentLength = Int(keyData[exponentIndex - 1])
        
        let modulus = keyData[9..<(9 + modulusLength)].base64URLEncodedString()
        let exponent = keyData[exponentIndex..<(exponentIndex + exponentLength)].base64URLEncodedString()

        let jwk: [String: Any] = [
            "kty": "RSA",
            "n": modulus,
            "e": exponent
        ]
        
        guard let jsonData = try? JSONSerialization.data(withJSONObject: jwk, options: .prettyPrinted) else {
            print("Error serializing JWK to JSON")
            return nil
        }
        
        return String(data: jsonData, encoding: .utf8)
    }
}





extension SecKey {
    func toPKCS8PublicKeyString() -> String? {
        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(self, &error) as Data? else {
            print("Error converting key to data: \(error!.takeRetainedValue().localizedDescription)")
            return nil
        }

        let attributes = SecKeyCopyAttributes(self)! as NSDictionary
        let keyType = attributes[kSecAttrKeyType as String] as! CFString

        if keyType == kSecAttrKeyTypeRSA {
            return wrapRSAPublicKeyInPKCS8String(keyData: keyData)
        } else if keyType == kSecAttrKeyTypeECSECPrimeRandom {
            return wrapECPublicKeyInPKCS8String(keyData: keyData)
        } else {
            print("Unsupported key type")
            return nil
        }
    }

    private func wrapRSAPublicKeyInPKCS8String(keyData: Data) -> String? {
        // PKCS#8 header for RSA public key
        let pkcs8Header: [UInt8] = [
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
            0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00
        ]

        var pkcs8Key = Data(pkcs8Header)
        pkcs8Key.append(keyData)

        let base64Key = pkcs8Key.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return """
        -----BEGIN PUBLIC KEY-----
        \(base64Key)
        -----END PUBLIC KEY-----
        """
    }

    private func wrapECPublicKeyInPKCS8String(keyData: Data) -> String? {
        // PKCS#8 header for EC public key
        let pkcs8Header: [UInt8] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
            0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
            0x42, 0x00
        ]

        var pkcs8Key = Data(pkcs8Header)
        pkcs8Key.append(keyData)

        let base64Key = pkcs8Key.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return """
        -----BEGIN PUBLIC KEY-----
        \(base64Key)
        -----END PUBLIC KEY-----
        """
    }
}
