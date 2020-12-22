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

final class VpnManager: NSObject {
  let vpnManager = NEVPNManager.shared();
  
  @available(iOS 9.0, *)
  func prepare(result: @escaping FlutterResult) {
    result(nil);
    self.vpnManager.loadFromPreferences {(error) -> Void in
      if error != nil {
        result(FlutterError(code: "Prepare error", message: error?.localizedDescription, details: nil))
      }
    }
  }

  @available(iOS 9.0, *)
  func connect(result: @escaping FlutterResult, username: NSString, password: NSString, address: NSString, primaryDNS: NSString? = "8.8.8.8", secondaryDNS: NSString? = "8.8.4.4") {
    let kcs = KeychainService()

    self.vpnManager.loadFromPreferences { (error) -> Void in

      if error != nil {
        print("VPN Preferences error: 1")
        VPNStateHandler.updateState(VPNStates.reasserting)
        result(FlutterError(code: "VPN Load Error", message: error?.localizedDescription, details: nil))
      } else {
        VPNStateHandler.updateState(VPNStates.connecting)
        let p = NEVPNProtocolIKEv2()

        p.username = username as String
        p.remoteIdentifier = address as String
        p.serverAddress = address as String
        
        p.deadPeerDetectionRate = .low

        kcs.save(key: "password", value: password as String)
        p.passwordReference = kcs.load(key: "password")
        p.authenticationMethod = .none

        p.useExtendedAuthentication = true
        p.disconnectOnSleep = false

        self.vpnManager.protocolConfiguration = p
        self.vpnManager.localizedDescription = "Wall One Privacy"
        self.vpnManager.isEnabled = true
        self.vpnManager.isOnDemandEnabled = true

        let connectRule = NEOnDemandRuleConnect()
        connectRule.interfaceTypeMatch = .any
        
        let evaluationRule = NEEvaluateConnectionRule(matchDomains: ["*.com", "*.net", "*.io", "*.me", "*.ru", "*.co", "*.uk"], andAction: NEEvaluateConnectionRuleAction.connectIfNeeded)
      
        evaluationRule.useDNSServers = [primaryDNS as! String, secondaryDNS as! String]
        
        let onDemandEvaluationRule = NEOnDemandRuleEvaluateConnection()
        onDemandEvaluationRule.connectionRules = [evaluationRule]
        onDemandEvaluationRule.interfaceTypeMatch = NEOnDemandRuleInterfaceType.any

        self.vpnManager.onDemandRules = [connectRule, onDemandEvaluationRule]

        self.vpnManager.saveToPreferences(completionHandler: { (error) -> Void in
          if error != nil {
            print("VPN Preferences error: 2")
            VPNStateHandler.updateState(VPNStates.reasserting)
            result(FlutterError(code: "Save Error", message: error?.localizedDescription, details: nil))
          } else {
            self.vpnManager.loadFromPreferences(completionHandler: { error in

              if error != nil {
                print("VPN Preferences error: 2")
                VPNStateHandler.updateState(VPNStates.reasserting)
                result(FlutterError(code: "Load 2 Error", message: error?.localizedDescription, details: nil))
              } else {
                var startError: NSError?

                do {
                  try self.vpnManager.connection.startVPNTunnel()
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
                  result(FlutterError(code: "Start Error", message: error?.localizedDescription, details: nil))
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

  func disconnect(result: @escaping FlutterResult) {
    result(nil)

    self.vpnManager.loadFromPreferences {(error) -> Void in
      if error != nil {
        print("vpn load errror")
      } else {
        print("vpn load success")
          
        self.vpnManager.isOnDemandEnabled = false
        self.vpnManager.onDemandRules = []
        
        self.vpnManager.saveToPreferences(completionHandler: { (error) -> Void in
          if error != nil {
            print("VPN Preferences error: 2")
            VPNStateHandler.updateState(VPNStates.reasserting)
          } else {
            VPNStateHandler.updateState(VPNStates.disconnecting)
            self.vpnManager.connection.stopVPNTunnel()
            VPNStateHandler.updateState(VPNStates.disconnected)
          }
        })
      }
    }
  }

  func getState(result: @escaping FlutterResult) {
    let status = self.vpnManager.connection.status

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

}

