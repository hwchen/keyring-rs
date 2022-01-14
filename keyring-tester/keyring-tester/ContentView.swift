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
        do {
            try PasswordOps.setPassword(service: service, user: user, password: passwordIn)
            alertTitle = "Success"
            alertMessage = "Password set!"
        } catch PasswordError.unexpected(let status) {
            alertTitle = "Failure"
            alertMessage = "Set Password failed: OSStatus \(status)"
        } catch {
            alertTitle = "Failure"
            alertMessage = "Set Password failed: \(error)"
        }
    }
    
    func get_password() {
        do {
            try passwordOut = PasswordOps.getPassword(service: service, user: user)
        } catch {
            passwordOut = ""
            showAlert = true
            alertTitle = "Failure"
            switch error {
            case PasswordError.notFound:
                alertMessage = "No item found for \(service) and \(user)"
            case PasswordError.notString(let data):
                var password = ""
                _ = transcode(data.makeIterator(), from: UTF8.self, to: UTF8.self, stoppingOnError: false, into: {
                    password.append(contentsOf: String(Unicode.Scalar($0)))
                })
                passwordOut = password
                alertMessage = "Password is not UTF-8 encoded, bytes have been replaced"
            case PasswordError.unexpected(let status):
                alertMessage = "Get Password failed: OSStatus \(status)"
            default:
                alertMessage = "Get Password failed: \(error)"
            }
        }
    }
    
    func delete_password() {
        do {
            try PasswordOps.deletePassword(service: service, user: user)
            passwordOut = ""
        } catch {
            showAlert = true
            alertTitle = "Failure"
            switch error {
            case PasswordError.notFound:
                passwordOut = ""
                alertMessage = "No keychain entry found for \(service) and \(user)"
            case PasswordError.unexpected(let status):
                alertMessage = "Delete Password failed: OSStatus \(status)"
            default:
                alertMessage = "Delete Password failed: \(error)"
            }
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
