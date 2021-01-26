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

import Flutter
import UIKit

@available(iOS 10.0, *)
public class SwiftFlutterVpnPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "flutter_vpn", binaryMessenger: registrar.messenger())
    let stateChannel = FlutterEventChannel(name: "flutter_vpn_states", binaryMessenger: registrar.messenger())
    
    let instance = SwiftFlutterVpnPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
    stateChannel.setStreamHandler(VPNStateHandler() as? FlutterStreamHandler & NSObjectProtocol)
    
    let manager = VpnManager()
    
    channel.setMethodCallHandler {
      (call: FlutterMethodCall, result: @escaping FlutterResult) -> Void in
      if call.method == "connect" {
        let args = call.arguments! as! [NSString: Any]
        let isOnDemandEnabled = args["onDemandEnable"] as? Int != nil ? args["onDemandEnable"] as! Int == 1 : true
        
        let primaryDNS = args["primaryDNS"] is NSNull ? nil : args["primaryDNS"] as? String
        let secondaryDNS = args["secondaryDNS"] is NSNull ? nil : args["secondaryDNS"] as? String
        
        let enablePFS = args["enablePFS"] as? Int != nil ? args["enablePFS"] as! Int == 1 : true;

        manager.connect(
          result: result,
          username: args["username"]! as! String,
          password: args["password"]! as! String,
          address: args["address"]! as! String,
          primaryDNS: primaryDNS,
          secondaryDNS: secondaryDNS,
          isOnDemandEnable: isOnDemandEnabled,
          enablePFS: enablePFS
        )
      } else if call.method == "disconnect" {
        manager.disconnect(result: result)
      } else if call.method == "getCurrentState" {
        manager.getState(result: result)
      } else if call.method == "initManager" || call.method == "prepare" {
        manager.prepare(result: result)
      } else if call.method == "isOnDemandEnabled" {
        manager.isOnDemandEnabled(result: result)
      }
    }
  }
}
