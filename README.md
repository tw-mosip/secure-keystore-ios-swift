# secure-keystore-ios-swift
Swift library to create and store keys in ios keychain and secure key enclave. Also helps to do encryption, decryption, and data signing.

## Installation

### Step 1: Add the SecureKeystore library to your project

To integrate the `SecureKeystore` library into your Xcode project, you need to add it as a dependency.

#### Using Swift Package Manager

1. Open your Xcode project.
2. Navigate to **File > Swift Packages > Add Package Dependency**.
3. Enter the following URL in the search bar:

    ```
    https://github.com/mosip/secure-keystore.git
    ```

4. Select the version you want to install.


## SecureKeystoreProtocol

The `SecureKeystoreProtocol` provides a standard interface for securely managing cryptographic keys and performing cryptographic operations in an iOS application. This protocol defines various methods to generate, store, retrieve, and use cryptographic keys, as well as to handle biometrics and keychain operations.

## Api References

### 1. `generateKeyPair(type: String, tag: String, isAuthRequired: Bool, authTimeout: Int32, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)`
Generates a new key pair.

- **Parameters:**
  - `type`: The type of the key pair (support for: RSA, EC, HMAC, AES).
  - `tag`: The tag used to identify the key pair in the keychain.
  - `isAuthRequired`: A Boolean indicating if user authentication is required.
  - `authTimeout`: The timeout for authentication.
  - `onSuccess`: A closure that gets called with the public key (PKCS8) string on successful key generation.
  - `onFailure`: A closure that gets called with an error code and message if the operation fails.

### 2. `deleteKeyPair(tag: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)`
Deletes an existing key pair.

- **Parameters:**
  - `tag`: The tag used to identify the key pair in the keychain.
  - `onSuccess`: A closure that gets called with a Boolean indicating the success of the operation.
  - `onFailure`: A closure that gets called with an error code and message if the operation fails.

### 3. `hasAlias(tag: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)`
Checks if a key pair with the specified tag exists.

- **Parameters:**
  - `tag`: The tag used to identify the key pair in the keychain.
  - `onSuccess`: A closure that gets called with a Boolean indicating if the alias exists.
  - `onFailure`: A closure that gets called with an error code and message if the operation fails.

### 4. `sign(signAlgorithm: String, alias: String, data: String, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)`
Signs data using the specified algorithm and key pair.

- **Parameters:**
  - `signAlgorithm`: The algorithm used for signing (support: RSA (.rsaSignatureMessagePKCS1v15SHA256), ECR1 (.ecdsaSignatureMessageX962SHA1)).
  - `alias`: The alias of the key pair used for signing.
  - `data`: The data to be signed.
  - `onSuccess`: A closure that gets called with the signed data as a string.
  - `onFailure`: A closure that gets called with an error code and message if the operation fails.

### 5. `storeGenericKey(publicKey: String, privateKey: String, account: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)`
Stores a generic key (public-private key pair) in the keychain.

- **Parameters:**
  - `publicKey`: The public key to store.
  - `privateKey`: The private key to store.
  - `account`: The account associated with the key.
  - `onSuccess`: A closure that gets called with a Boolean indicating the success of the operation.
  - `onFailure`: A closure that gets called with an error code and message if the operation fails.

### 6. `retrieveGenericKey(account: String, onSuccess: @escaping (String?, String?) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)`
Retrieves a generic key (public-private key pair) from the keychain.

- **Parameters:**
  - `account`: The account associated with the key.
  - `onSuccess`: A closure that gets called with the retrieved public and private keys as strings.
  - `onFailure`: A closure that gets called with an error code and message if the operation fails.

### 7. `hasBiometricsEnabled() -> Bool`
Checks if biometrics (Face ID/Touch ID) are enabled on the device.

- **Returns:**
  - A Boolean indicating if biometrics are enabled.

### 8. `updatePopup(title: String, desc: String)`  
Updates the title and description of the authentication popup.`static` method so sets for all biometric instances.

- **Parameters:**
  - `title`: The title of the popup.
  - `desc`: The description of the popup.

### 9. `generateKey(alias: String, authRequired: Bool, authTimeout: Int32, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)`
Generates a asymmetric(.eciesEncryptionCofactorVariableIVX963SHA256AESGCM) key with optional user authentication on secure enclave, mainly used for encryption/decryption using AES_GCM.

- **Parameters:**
  - `alias`: The alias for the key.
  - `authRequired`: A Boolean indicating if user authentication is required.
  - `authTimeout`: The timeout for authentication.
  - `onSuccess`: A closure that gets called with a Boolean indicating the success of the operation.
  - `onFailure`: A closure that gets called with an error code and message if the operation fails.

### 10. `encryptData(alias: String, data: String, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)`
Encrypts data using the specified key.The key should be of type EC curve.(256 bytes)

- **Parameters:**
  - `alias`: The alias of the key used for encryption.
  - `data`: The data to be encrypted.
  - `onSuccess`: A closure that gets called with the encrypted data as a string.
  - `onFailure`: A closure that gets called with an error code and message if the operation fails.

### 11. `decryptData(alias: String, data: String, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)`
Decrypts data using the specified key. The key should be of type EC curve.(256 bytes)

- **Parameters:**
  - `alias`: The alias of the key used for decryption.
  - `data`: The data to be decrypted.
  - `onSuccess`: A closure that gets called with the decrypted data as a string.
  - `onFailure`: A closure that gets called with an error code and message if the operation fails.

### 12. `generateHmacshaKey(alias: String, onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)`
Generates an HMAC-SHA key.

- **Available:**
  - iOS 13.0 and later.

- **Parameters:**
  - `alias`: The alias for the key.
  - `onSuccess`: A closure that gets called with a Boolean indicating the success of the operation.
  - `onFailure`: A closure that gets called with an error code and message if the operation fails.

### 13. `generateHmacSha(alias: String, data: String, onSuccess: @escaping (String?) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)`
Generates an HMAC-SHA signature using the specified key.

- **Available:**
  - iOS 13.0 and later.

- **Parameters:**
  - `alias`: The alias of the key used for generating the HMAC.
  - `data`: The data to be signed.
  - `onSuccess`: A closure that gets called with the generated HMAC as a string.
  - `onFailure`: A closure that gets called with an error code and message if the operation fails.

### 14. `clearKeys(onSuccess: @escaping (Bool) -> Void, onFailure: @escaping(_ code: String, _ message: String) -> Void)`
Clears all keys stored in the keychain.

- **Parameters:**
  - `onSuccess`: A closure that gets called with a Boolean indicating the success of the operation.
  - `onFailure`: A closure that gets called with an error code and message if the operation fails.

### 15. `retrieveKey(tag: String, onSuccess: @escaping (String) -> Void, onFailure: @escaping(_ code: String,_ message: String)->Void)`
Retrieves the public key from the keychain by its tag.(PKCS8)

- **Parameters:**
  - `tag`: The tag used to identify the key.
  - `onSuccess`: A closure that gets called with the retrieved key as a string.
  - `onFailure`: A closure that gets called with an error code and message if the operation fails.

