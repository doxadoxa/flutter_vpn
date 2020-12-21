/**
 * Copyright (C) 2019 Jerry Wang, Jason C.H
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

import Foundation
import NetworkExtension
import Security

// Identifiers
let serviceIdentifier = "MySerivice"
let userAccount = "authenticatedUser"
let accessGroup = "MySerivice"

let vpnManager = NEVPNManager.shared();

// Arguments for the keychain queries
var kSecAttrAccessGroupSwift = NSString(format: kSecClass)

let kSecClassValue = kSecClass as CFString
let kSecAttrAccountValue = kSecAttrAccount as CFString
let kSecValueDataValue = kSecValueData as CFString
let kSecClassGenericPasswordValue = kSecClassGenericPassword as CFString
let kSecAttrServiceValue = kSecAttrService as CFString
let kSecMatchLimitValue = kSecMatchLimit as CFString
let kSecReturnDataValue = kSecReturnData as CFString
let kSecMatchLimitOneValue = kSecMatchLimitOne as CFString
let kSecAttrGenericValue = kSecAttrGeneric as CFString
let kSecAttrAccessibleValue = kSecAttrAccessible as CFString

class KeychainService: NSObject {
    func save(key: String, value: String) {
        let keyData: Data = key.data(using: String.Encoding(rawValue: String.Encoding.utf8.rawValue), allowLossyConversion: false)!
        let valueData: Data = value.data(using: String.Encoding(rawValue: String.Encoding.utf8.rawValue), allowLossyConversion: false)!

        let keychainQuery = NSMutableDictionary()
        keychainQuery[kSecClassValue as! NSCopying] = kSecClassGenericPasswordValue
        keychainQuery[kSecAttrGenericValue as! NSCopying] = keyData
        keychainQuery[kSecAttrAccountValue as! NSCopying] = keyData
        keychainQuery[kSecAttrServiceValue as! NSCopying] = "VPN"
        keychainQuery[kSecAttrAccessibleValue as! NSCopying] = kSecAttrAccessibleAlwaysThisDeviceOnly
        keychainQuery[kSecValueData as! NSCopying] = valueData
        // Delete any existing items
        SecItemDelete(keychainQuery as CFDictionary)
        SecItemAdd(keychainQuery as CFDictionary, nil)
    }

    func load(key: String) -> Data {
        let keyData: Data = key.data(using: String.Encoding(rawValue: String.Encoding.utf8.rawValue), allowLossyConversion: false)!
        let keychainQuery = NSMutableDictionary()
        keychainQuery[kSecClassValue as! NSCopying] = kSecClassGenericPasswordValue
        keychainQuery[kSecAttrGenericValue as! NSCopying] = keyData
        keychainQuery[kSecAttrAccountValue as! NSCopying] = keyData
        keychainQuery[kSecAttrServiceValue as! NSCopying] = "VPN"
        keychainQuery[kSecAttrAccessibleValue as! NSCopying] = kSecAttrAccessibleAlwaysThisDeviceOnly
        keychainQuery[kSecMatchLimit] = kSecMatchLimitOne
        keychainQuery[kSecReturnPersistentRef] = kCFBooleanTrue

        var result: AnyObject?
        let status = withUnsafeMutablePointer(to: &result) { SecItemCopyMatching(keychainQuery, UnsafeMutablePointer($0)) }

        if status == errSecSuccess {
            if let data = result as! NSData? {
                if let value = NSString(data: data as Data, encoding: String.Encoding.utf8.rawValue) {}
                return data as Data
            }
        }
        return "".data(using: .utf8)!
    }
}

@available(iOS 9.0, *)
func prepare(result: FlutterResult) {
    result(nil);
    vpnManager.loadFromPreferences {(error) -> Void in 
        if error != nil {
            print("vpn load errror")
        } else {
            print("vpn load success")
        }
    }
}

@available(iOS 9.0, *)
func connect(result: FlutterResult, username: NSString, password: NSString, address: NSString) {
    let kcs = KeychainService()
    result(nil)

    vpnManager.loadFromPreferences { (error) -> Void in

        if error != nil {
            print("VPN Preferences error: 1")
            VPNStateHandler.updateState(VPNStates.reasserting)
        } else {
            VPNStateHandler.updateState(VPNStates.connecting)
            let p = NEVPNProtocolIKEv2()

            p.username = username as String
            p.remoteIdentifier = address as String
            p.serverAddress = address as String

            kcs.save(key: "password", value: password as String)
            p.passwordReference = kcs.load(key: "password")
            p.authenticationMethod = NEVPNIKEAuthenticationMethod.none

            p.useExtendedAuthentication = true
            p.disconnectOnSleep = false

            vpnManager.protocolConfiguration = p
            self.vpnManager.localizedDescription = "Wall One Privacy"
            vpnManager.isEnabled = true
            vpnManager.isOnDemandEnabled = true

            let connectRule = NEOnDemandRuleConnect();
            connectRule.interfaceTypeMatch = .any

            let disconnectRule = NEOnDemandRuleDisconnect();
            disconnectRule.interfaceTypeMatch = .any

            vpnManager.onDemandRules = [connectRule, disconnectRule];

            vpnManager.saveToPreferences(completionHandler: { (error) -> Void in
                if error != nil {
                    print("VPN Preferences error: 2")
                    VPNStateHandler.updateState(VPNStates.reasserting)
                } else {
                    vpnManager.loadFromPreferences(completionHandler: { error in

                        if error != nil {
                            print("VPN Preferences error: 2")
                            VPNStateHandler.updateState(VPNStates.reasserting)
                        } else {
                            var startError: NSError?

                            do {
                                try vpnManager.connection.startVPNTunnel()
                            } catch let error as NSError {
                                startError = error
                                VPNStateHandler.updateState(VPNStates.reasserting)
                                print(startError)
                            } catch {
                                print("Fatal Error")
                                fatalError()
                            }
                            if startError != nil {
                                print("VPN Preferences error: 3")
                                print(startError)
                            } else {
                                print("VPN started successfully..")
                                VPNStateHandler.updateState(VPNStates.connected)
                            }
                        }
                    })
                }
            })
        }
    }
}

func disconnect(result: FlutterResult) {
    result(nil)

    vpnManager.loadFromPreferences {(error) -> Void in 
        if error != nil {
            print("vpn load errror")
        } else {
            print("vpn load success")

            VPNStateHandler.updateState(VPNStates.disconnecting)
            vpnManager.connection.stopVPNTunnel()
            VPNStateHandler.updateState(VPNStates.disconnected)
        }
    }    
}

func getState(result: FlutterResult) {
    let status = vpnManager.connection.status

    switch status {
    case .connecting:
        result(VPNStates.connecting)
    case .connected:
        result(VPNStates.connected)
    case .disconnecting:
        result(VPNStates.disconnecting)
    case .disconnected:
        result(VPNStates.disconnected)
    case .invalid:
        result(VPNStates.disconnected)
    case .reasserting:
        result(VPNStates.reasserting)
    default:
        result(VPNStates.reasserting)
    }  
}
