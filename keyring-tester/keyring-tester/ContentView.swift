//
//  ContentView.swift
//  keyring-tester
//
//  Created by Daniel Brotsky on 12/5/21.
//

import SwiftUI

struct ContentView: View {
    @State var service = "test-service"
    @State var user = "test-user"
    @State var passwordIn = "test-password"
    @State var passwordOut = ""
    @State var showAlert = false
    @State var alertTitle = ""
    @State var alertMessage = ""
    
    var body: some View {
        Form {
            Section("Service Name") {
                TextField("Service Name", text: $service)
                    .textInputAutocapitalization(.never)
            }
            Section("User Name") {
                TextField("User Name", text: $user)
                    .textInputAutocapitalization(.never)
            }
            Section("Set or Update Password") {
                TextField("Password to Set", text: $passwordIn)
                    .textInputAutocapitalization(.never)
                Button("Set Password") {
                    add_or_update_password()
                }
            }
            Section("Get or Delete Password") {
                Button("Get Password") {
                    get_password()
                }
                Text(passwordOut)
                Button("Delete Password") {
                    delete_password()
                }
            }
        }
        .alert(isPresented: $showAlert) {
            Alert(title: Text("\(alertTitle)"),
                  message: Text("\(alertMessage)"))
        }
    }
    
    func add_or_update_password() {
        if passwordIn.isEmpty {
            alertTitle = "Failure"
            alertMessage = "Can't set empty password; use Delete Password instead."
        }
        showAlert = true
        alertTitle = "Success"
        alertMessage = "Password set!"
        let password = passwordIn.data(using: String.Encoding.utf8)!
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: user,
            kSecAttrService as String: service,
            kSecValueData as String: password,
        ]
        var status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
            alertMessage = "Password updated!"
            query.removeValue(forKey: kSecValueData as String)
            let update: [String: Any] = [kSecValueData as String: password]
            status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        }
        if status != errSecSuccess {
            alertTitle = "Failure"
            alertMessage = "Set Password failed: OSStatus \(status)"
        }
    }
    
    func get_password() {
        passwordOut = ""
        showAlert = true
        alertTitle = "Failure"
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: user,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess {
            if let existingItem = item as? [String : Any],
               let passwordData = existingItem[kSecValueData as String] as? Data,
               let password = String(data: passwordData, encoding: String.Encoding.utf8) {
                showAlert = false
                passwordOut = password
            } else {
                alertMessage = "Bad password data in keychain"
            }
        } else if status == errSecItemNotFound {
            alertMessage = "No item found for \(service) and \(user)"
        } else {
            alertMessage = "Get Password failed: OSStatus \(status)"
        }
    }
    
    func delete_password() {
        showAlert = true
        alertTitle = "Failure"
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: user,
            kSecAttrService as String: service,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecSuccess {
            passwordOut = ""
            showAlert = false
        } else if status == errSecItemNotFound {
            passwordOut = ""
            alertMessage = "No keychain entry found for \(service) and \(user)"
        } else {
            alertMessage = "Delete Password failed: OSStatus \(status)"
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
