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
        showAlert = true
        guard !passwordIn.isEmpty else {
            alertTitle = "Failure"
            alertMessage = "Can't set empty password; use Delete Password instead."
            return
        }
        let status = KeyringSetPassword(service as CFString, user as CFString, passwordIn as CFString)
        if status == errSecSuccess {
            alertTitle = "Success"
            alertMessage = "Password set!"
        } else {
            alertTitle = "Failure"
            alertMessage = "Set Password failed: OSStatus \(status)"
        }
    }
    
    func get_password() {
        var password: CFString?
        let status = KeyringCopyPassword(service as CFString, user as CFString, &password)
        if status == errSecSuccess {
            passwordOut = password! as String
        } else {
            passwordOut = ""
            showAlert = true
            alertTitle = "Failure"
            if status == errSecItemNotFound {
                alertMessage = "No item found for \(service) and \(user)"
            } else {
                alertMessage = "Get Password failed: OSStatus \(status)"
            }
        }
    }
    
    func delete_password() {
        let status = KeyringDeletePassword(service as CFString, user as CFString)
        if status == errSecSuccess {
            passwordOut = ""
        } else {
            showAlert = true
            alertTitle = "Failure"
            if status == errSecItemNotFound {
                passwordOut = ""
                alertMessage = "No keychain entry found for \(service) and \(user)"
            } else {
                alertMessage = "Delete Password failed: OSStatus \(status)"
            }
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
