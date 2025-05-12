//
//  SecureKeyManager.swift
//  SecKeyManage


import Foundation
import CryptoKit
import LocalAuthentication
import Security

class SecureKeyManager {
    static let shared = SecureKeyManager()

    private let service = "com.example.PasswordManager"
    private let account = "encryptionKey"

    // MARK: - Public Interface

    /// Retrieve AES key (Face ID first, fallback to password)
    func getSymmetricKey(masterPassword: String?, completion: @escaping (SymmetricKey?) -> Void) {
        if let key = retrieveKeyFromKeychain() {
            completion(key)
        } else if let password = masterPassword {
            let key = deriveKeyFromPassword(password)
            completion(key)
        } else {
            authenticateWithBiometrics { success in
                if success {
                    completion(self.retrieveKeyFromKeychain())
                } else {
                    completion(nil)
                }
            }
        }
    }

    /// Save randomly generated key to Keychain (with Face ID/Touch ID access)
    func generateAndStoreKey() -> SymmetricKey {
        let key = SymmetricKey(size: .bits256)
        let _ = storeKeyInKeychain(key)
        return key
    }

    /// Export key as base64 (for backup)
    func exportKey() -> String? {
        guard let key = retrieveKeyFromKeychain() else { return nil }
        return key.withUnsafeBytes { Data($0).base64EncodedString() }
    }

    /// Import key from base64 (for recovery)
    func importKey(base64: String) -> Bool {
        guard let data = Data(base64Encoded: base64) else { return false }
        let key = SymmetricKey(data: data)
        return storeKeyInKeychain(key)
    }

    // MARK: - Encryption & Decryption

    func encrypt(data: Data, with key: SymmetricKey) -> Data? {
        do {
            let sealedBox = try AES.GCM.seal(data, using: key)
            return sealedBox.combined
        } catch {
            print("Encryption failed: \(error)")
            return nil
        }
    }

    func decrypt(data: Data, with key: SymmetricKey) -> Data? {
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: data)
            return try AES.GCM.open(sealedBox, using: key)
        } catch {
            print("Decryption failed: \(error)")
            return nil
        }
    }

    // MARK: - Internals

    private func deriveKeyFromPassword(_ password: String) -> SymmetricKey {
        let salt = "fixed-salt-value".data(using: .utf8)! // Use a stored, random salt in production
        let keyData = PBKDF2SHA256(password: password, salt: salt, keyByteCount: 32, rounds: 100_000)
        return SymmetricKey(data: keyData)
    }

    private func retrieveKeyFromKeychain() -> SymmetricKey? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        if status == errSecSuccess, let data = dataTypeRef as? Data {
            return SymmetricKey(data: data)
        }
        return nil
    }

    private func storeKeyInKeychain(_ key: SymmetricKey) -> Bool {
        let keyData = key.withUnsafeBytes { Data($0) }

        let access = SecAccessControlCreateWithFlags(nil,
                                                     kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                     .userPresence,
                                                     nil)

        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: keyData,
            kSecAttrAccessControl as String: access as Any,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIAllow
        ]

        SecItemDelete(attributes as CFDictionary) // Delete if exists
        let status = SecItemAdd(attributes as CFDictionary, nil)
        return status == errSecSuccess
    }

    private func authenticateWithBiometrics(completion: @escaping (Bool) -> Void) {
        let context = LAContext()
        var error: NSError?
        
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                   localizedReason: "Unlock your vault") { success, _ in
                DispatchQueue.main.async {
                    completion(success)
                }
            }
        } else {
            completion(false)
        }
    }

    // MARK: - PBKDF2 (password to key)
    private func PBKDF2SHA256(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data {
        let passwordData = password.data(using: .utf8)!
        var derivedKeyData = Data(repeating: 0, count: keyByteCount)
        derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
                _ = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                          password, passwordData.count,
                                          saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                                          CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                          UInt32(rounds),
                                          derivedKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), keyByteCount)
            }
        }
        return derivedKeyData
    }
}

// ⚠️ CommonCrypto を使うので bridging header に #import <CommonCrypto/CommonCrypto.h> が必要です
