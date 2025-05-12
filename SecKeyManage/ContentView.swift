//
//  ContentView.swift
//  SecKeyManage
//


import SwiftUI

struct EncryptionSampleView: View {
    @State private var inputText = ""
    @State private var encryptedData: Data?
    @State private var decryptedText = ""
    @State private var errorMessage = ""

    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                TextField("入力するテキスト", text: $inputText)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .padding()
                
                Button("鍵を生成して保存") {
                    let key = SecureKeyManager.shared.generateAndStoreKey()
                    print("鍵を保存: \(key)")
                }

                Button("暗号化") {
                    SecureKeyManager.shared.getSymmetricKey(masterPassword: nil) { key in
                        guard let key = key else {
                            errorMessage = "鍵の取得に失敗"
                            return
                        }
                        if let data = inputText.data(using: .utf8),
                           let encrypted = SecureKeyManager.shared.encrypt(data: data, with: key) {
                            encryptedData = encrypted
                            errorMessage = ""
                        } else {
                            errorMessage = "暗号化に失敗"
                        }
                    }
                }

                if let encryptedData = encryptedData {
                    Text("暗号化データ (base64):")
                        .font(.caption)
                    ScrollView {
                        Text(encryptedData.base64EncodedString())
                            .font(.system(size: 12, design: .monospaced))
                            .padding()
                            .background(Color.gray.opacity(0.1))
                            .cornerRadius(8)
                    }
                    .frame(height: 100)
                }

                Button("復号化") {
                    SecureKeyManager.shared.getSymmetricKey(masterPassword: nil) { key in
                        guard let key = key, let encrypted = encryptedData else {
                            errorMessage = "復号化前のデータまたは鍵が無い"
                            return
                        }
                        if let decrypted = SecureKeyManager.shared.decrypt(data: encrypted, with: key),
                           let text = String(data: decrypted, encoding: .utf8) {
                            decryptedText = text
                            errorMessage = ""
                        } else {
                            errorMessage = "復号化に失敗"
                        }
                    }
                }

                Text("復号化結果: \(decryptedText)")
                    .padding()

                if !errorMessage.isEmpty {
                    Text(errorMessage)
                        .foregroundColor(.red)
                }

                Spacer()
            }
            .navigationTitle("暗号化デモ")
            .padding()
        }
    }
}

#Preview {
    EncryptionSampleView()
}
