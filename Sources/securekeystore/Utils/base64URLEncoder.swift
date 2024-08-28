import Foundation

extension Data {
    func base64URLEncodedString() -> String {
        var base64 = self.base64EncodedString()
        base64 = base64
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return base64
    }
}
