//
//  PasswordOps.swift
//  ios-tester
//
//  This is a Swift wrapper for the external C wrapper for the Rust static library.
//  Making this a separate class allows for better error handling and isolation,
//  as well as the ability to do automated testing.
//

import Foundation

enum PasswordError: Error {
    case notFound
    case notString(Data)
    case unexpected(OSStatus)
}

class PasswordOps {
    static func setPassword(service: String, user: String, password: String) throws {
        let status = KeyringSetPassword(service as CFString, user as CFString, password as CFString)
        guard status == errSecSuccess else {
            throw PasswordError.unexpected(status)
        }
    }
    
    static func getPassword(service: String, user: String) throws -> String {
        var result: CFData?
        let status = KeyringCopyPassword(service as CFString, user as CFString, &result)
        switch status {
        case errSecItemNotFound:
            throw PasswordError.notFound
        case errSecSuccess, errSecDecode:
            let data = result! as Data
            if let password = String.init(bytes: data, encoding: .utf8) {
                return password
            } else {
                throw PasswordError.notString(data)
            }
        default:
            throw PasswordError.unexpected(status)
        }
    }
    
    static func deletePassword(service: String, user: String) throws {
        let status = KeyringDeletePassword(service as CFString, user as CFString)
        switch status {
        case errSecItemNotFound:
            throw PasswordError.notFound
        case errSecSuccess:
            return
        default:
            throw PasswordError.unexpected(status)
        }
    }
    
}
