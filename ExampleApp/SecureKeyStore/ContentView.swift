import SwiftUI
import securekeystore

struct ContentView: View {
    @State private var message = ""
    @State private var alias = "TestKey"
    @State private var generated = false
    
    let secureKeystore = SecureKeystoreImpl()
    
    var body: some View {
        VStack {
            TextField("Alias", text: $alias)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()
            
            Button("Generate RSA Key Pair") {
                secureKeystore.generateKey( alias: alias, authRequired: false, authTimeout: 0, onSuccess: { success in
                    message = "RSA Key Pair Generated Successfully"
                    generated = true
                }, onFailure: { code, message in
                    self.message = "Failed to generate RSA Key Pair: \(message)"
                })
            }
            .padding()
            .disabled(generated)
            
            Button("Check Key Existence") {
                secureKeystore.hasAlias(tag: alias, onSuccess: { exists in
                    message = exists ? "Key exists in Keychain" : "Key does not exist"
                }, onFailure: { code, message in
                    self.message = "Error checking key existence: \(message)"
                })
            }
            .padding()
            
            Button("Encrypt") {
                secureKeystore.encryptData(alias: alias, data: "String", onSuccess: { signature in
                    message = "Signed data: \(signature)"
                }, onFailure: { code, message in
                    self.message = "Failed to sign data: \(message)"
                })
            }
            .padding()
            .disabled(!generated)
            
            Button("Delete RSA Key Pair") {
                secureKeystore.deleteKeyPair(tag: alias, onSuccess: { success in
                    message = "Key pair deleted successfully"
                    generated = false                }, onFailure: { code, message in
                    self.message = "Failed to delete key pair: \(message)"
                })
            }
            .padding()
            .disabled(!generated)
            
            Text(message)
                .padding()
                .multilineTextAlignment(.center)
                .foregroundColor(.blue)
        }
        .padding()
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
