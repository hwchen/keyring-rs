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
    @State var password_in = "test-password"
    @State var password_out = ""
    @State var show_alert = false
    @State var action = "Set Password"
    @State var errMessage = ""
    @State var opStatus: OSStatus = 0;
    
    var body: some View {
        Form {
            Section("Service Name") {
                TextField("Service Name", text: $service)
            }
            Section("User Name") {
                TextField("User Name", text: $user)
            }
            Section("Password") {
                TextField("Password to Set", text: $password_in)
                Button("Set Password") {
                    action = "Set Password"
                    opStatus = add_password()
                    if opStatus == errSecSuccess {
                        password_in = "[Already set, use get!]"
                    } else {
                        show_alert = true
                    }
                }
            }
            Section("Get Password") {
                Button("Get Password") {
                    action = "Get Password"
                    opStatus = get_password()
                    if opStatus != errSecSuccess {
                        password_out = "[Error retrieving password]"
                        show_alert = true
                    }
                }
                Text(password_out)
            }
        }
        .alert(isPresented: $show_alert) {
            Alert(
                title: Text("Operation Failure"),
                message: Text("\(action) failed: \(errMessage)"))
        }
    }
    
    func add_password() -> OSStatus {
        let password = password_in.data(using: String.Encoding.utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: user,
            kSecAttrService as String: service,
            kSecValueData as String: password,
        ]
        var item: CFTypeRef?
        let status = SecItemAdd(query as CFDictionary, &item)
        print("item: \(String(describing:item))")
        errMessage = "OSStatus \(status)"
        return status
    }
    
    func get_password() -> OSStatus {
        password_out = ""
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: user,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        print("item: \(String(describing:item))")
        if status == errSecSuccess {
            if let existingItem = item as? [String : Any],
               let passwordData = existingItem[kSecValueData as String] as? Data,
               let password = String(data: passwordData, encoding: String.Encoding.utf8) {
                password_out = password
            } else {
                errMessage = "Bad password data"
                return errSecDecode
            }
        } else if status == errSecItemNotFound {
            errMessage = "No item found for \(service) and \(user)"
        } else {
            errMessage = "OSStatus \(status)"
        }
        return status
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
