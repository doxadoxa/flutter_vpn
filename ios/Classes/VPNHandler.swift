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
          if NSString(data: data as Data, encoding: String.Encoding.utf8.rawValue) != nil {}
            return data as Data
        }
    }
    return "".data(using: .utf8)!
  }
}

final class VpnManager: NSObject {
  private let _vpnManager: NEVPNManager = NEVPNManager.shared()
  private let _localizedDescription = "Wall One Privacy"
  private var _timer: Timer?
  
  public var state: VPNStates = .disconnected {
    didSet {
      guard state != oldValue else { return }
      
      VPNStateHandler.updateState(state)
    }
  }
  
  @available(iOS 10.0, *)
  func prepare(result: @escaping FlutterResult) {
    self._vpnManager.loadFromPreferences{ (error) -> Void in
      if error != nil {
        result(false)
      } else {
        self.updateState(VpnManager.convertState(status: self._vpnManager.connection.status))
        result(true)
      }
    }
    
    self.initTimer()
  }
  
  deinit {
    self._timer?.invalidate()
  }

  @available(iOS 10.0, *)
  public func connect(result: @escaping FlutterResult, username: String, password: String,
                      address: String, primaryDNS: String?, secondaryDNS: String?, isOnDemandEnable: Bool = true, enablePFS: Bool = true) {

    self._timer?.invalidate()
    self._timer = nil
    
    let kcs = KeychainService()

    self.updateState(VPNStates.connecting)
    
    self._vpnManager.loadFromPreferences { (error) -> Void in
      
      if error != nil {
        self.updateState(VPNStates.reasserting)
        result(FlutterError(code: "VPN Load Error", message: error?.localizedDescription, details: nil))
      } else {
        let vpnManager = self._vpnManager
        
        let p = NEVPNProtocolIKEv2()

        p.username = username as String
        p.remoteIdentifier = address as String
        p.serverAddress = address as String

        kcs.save(key: "password", value: password as String)
        p.passwordReference = kcs.load(key: "password")
        p.authenticationMethod = .none

        p.useExtendedAuthentication = true
        p.disconnectOnSleep = false
        p.deadPeerDetectionRate = .low

        p.ikeSecurityAssociationParameters.lifetimeMinutes = 1440
        p.childSecurityAssociationParameters.lifetimeMinutes = 1440
        p.enablePFS = enablePFS;

        vpnManager.protocolConfiguration = p
        vpnManager.localizedDescription = self._localizedDescription
        vpnManager.isEnabled = true
        
        vpnManager.isOnDemandEnabled = isOnDemandEnable
        var rules: Array<NEOnDemandRule> = []

        if isOnDemandEnable == true {
          let connectRule = NEOnDemandRuleConnect()
          connectRule.interfaceTypeMatch = .any
          rules.append(connectRule)
        }

        if primaryDNS != nil && secondaryDNS != nil && !primaryDNS!.isEmpty && !primaryDNS!.isEmpty {
          vpnManager.isOnDemandEnabled = true
          
          let evaluationRule = NEEvaluateConnectionRule(matchDomains: TLD.all, andAction: .connectIfNeeded)
          evaluationRule.useDNSServers = [primaryDNS!, secondaryDNS!]
          
          print(primaryDNS!)
          print(secondaryDNS!)

          let dnsRule = NEOnDemandRuleEvaluateConnection()
          dnsRule.connectionRules = [evaluationRule]
          dnsRule.interfaceTypeMatch = .any

          rules.append(dnsRule)
        }

        vpnManager.onDemandRules = rules

        vpnManager.saveToPreferences { (error) -> Void in
          if error != nil {
            self.updateState(VPNStates.reasserting)
            result(FlutterError(code: "Save Error", message: error?.localizedDescription, details: nil))
            
          } else {
            vpnManager.loadFromPreferences { (error) -> Void in

              if error != nil {
                self.updateState(VPNStates.reasserting)
                result(FlutterError(code: "Reload Error", message: error?.localizedDescription, details: nil))
              } else {
                var startError: NSError?

                do {
                  try vpnManager.connection.startVPNTunnel()
                } catch let error as NSError {
                  startError = error
                  self.updateState(VPNStates.reasserting)
                  result(FlutterError(code: "Start Error", message: startError?.localizedDescription, details: nil))
                } catch {
                  fatalError()
                }
              
                if startError != nil {
                  result(FlutterError(code: "Start Error", message: startError?.localizedDescription, details: nil))
                } else {
                  self._timer?.invalidate()

                  self.updateState(VPNStates.connected)
                  self.initTimer(5.0)
                  result(nil)
                }
              }
            }
          }
        }
      }
    }
  }

  public func disconnect(result: @escaping FlutterResult) {
    result(nil)

    self._vpnManager.loadFromPreferences {[weak self] (error) -> Void in
      guard let self = self else { return }
      
      if error == nil {
        self._vpnManager.isOnDemandEnabled = false
        self._vpnManager.onDemandRules = []
        
        self._vpnManager.saveToPreferences(completionHandler: { [weak self] (error) -> Void in
          guard let self = self else { return }
          
          if error != nil {
            self.updateState(VPNStates.reasserting)
          } else {
            self.updateState(VPNStates.disconnecting)
            self._vpnManager.connection.stopVPNTunnel()
            self.updateState(VPNStates.disconnected)
          }
        })
      }
    }
  }

  public func getState(result: @escaping FlutterResult) {
    let status = self._vpnManager.connection.status
    result(VpnManager.convertState(status: status).rawValue)
  }
  
  public func isOnDemandEnabled(result: @escaping FlutterResult) {
    result(self._vpnManager.isOnDemandEnabled)
  }
  
  private func updateState(_ state: VPNStates) {
    self.state = state
  }

  @available(iOS 10.0, *)
  private func initTimer(_ delay: Double = 0) {
     if self._timer == nil {
      DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
        let timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { timer in
          self.state = VpnManager.convertState(status: self._vpnManager.connection.status)
        }
        
        timer.tolerance = 0.5
              
        self._timer = timer;
      }
    }
  }
  
  private static func convertState(status: NEVPNStatus) -> VPNStates {
    switch status {
      case .connecting:
        return VPNStates.connecting
      case .connected:
        return VPNStates.connected
      case .disconnecting:
        return VPNStates.disconnecting
      case .disconnected:
        return VPNStates.disconnected
      case .invalid:
        return VPNStates.disconnected
      case .reasserting:
        return VPNStates.reasserting
      default:
        return VPNStates.reasserting
    }
  }
}

