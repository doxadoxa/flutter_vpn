import 'dart:io';

///
/// Copyright (C) 2018 Jason C.H
/// This library is free software; you can redistribute it and/or
/// modify it under the terms of the GNU Lesser General Public
/// License as published by the Free Software Foundation; either
/// version 2.1 of the License, or (at your option) any later version.
///
/// This library is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/// Lesser General Public License for more details.
///

import 'package:flutter/material.dart';
import 'package:flutter_vpn/flutter_vpn.dart';

void main() => runApp(MyApp());

class MyApp extends StatefulWidget {
  @override
  _MyAppState createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final _addressController =
      TextEditingController(text: "vpn-japan-server-0.wall.one");
  final _usernameController = TextEditingController(text: "wall");
  final _passwordController = TextEditingController(text: "Wall-2020");
  final _primaryDnsController = TextEditingController();
  final _secondaryDnsController = TextEditingController();

  var isOnDemandEnabled = false;

  var state = FlutterVpnState.disconnected;
  var charonState = CharonErrorState.NO_ERROR;

  void initIsOnDemandEnabled() async {
    setState(() async {
      isOnDemandEnabled = await FlutterVpn.isOnDemandEnabled();
    });
  }

  @override
  void initState() {
    FlutterVpn.prepare();
    FlutterVpn.onStateChanged.listen((s) => setState(() => state = s));
    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Flutter VPN'),
        ),
        body: ListView(
          padding: const EdgeInsets.all(15.0),
          children: <Widget>[
            RichText(
                text:
                    TextSpan(style: TextStyle(color: Colors.black), children: [
              TextSpan(text: 'Current State: '),
              TextSpan(
                  text: state.toString(),
                  style: TextStyle(fontWeight: FontWeight.bold))
            ])),
            RichText(
                text:
                    TextSpan(style: TextStyle(color: Colors.black), children: [
              TextSpan(text: 'Current Charon State: '),
              TextSpan(
                  text: charonState.toString(),
                  style: TextStyle(fontWeight: FontWeight.bold))
            ])),
            TextFormField(
              controller: _addressController,
              decoration: InputDecoration(icon: Icon(Icons.map)),
            ),
            TextFormField(
              controller: _usernameController,
              decoration: InputDecoration(icon: Icon(Icons.person_outline)),
            ),
            TextFormField(
              controller: _passwordController,
              obscureText: true,
              decoration: InputDecoration(icon: Icon(Icons.lock_outline)),
            ),
            TextFormField(
              decoration: InputDecoration(
                  labelText: "Primary DNS", icon: Icon(Icons.dns_outlined)),
              controller: _primaryDnsController,
            ),
            TextFormField(
              decoration: InputDecoration(
                  labelText: "Secondary DNS", icon: Icon(Icons.dns_outlined)),
              controller: _secondaryDnsController,
            ),
            if (Platform.isIOS)
              SwitchListTile(
                  title: Text("On Demand Mode"),
                  value: isOnDemandEnabled,
                  onChanged: (value) {
                    setState(() => isOnDemandEnabled = value);
                    print(isOnDemandEnabled);
                  }),
            RaisedButton(
              child: Text('Connect'),
              onPressed: () async {
                try {
                  await FlutterVpn.connect(_addressController.text,
                      _usernameController.text, _passwordController.text,
                      isOnDemandEnabled: isOnDemandEnabled,
                      dns: [
                        _primaryDnsController.text,
                        _secondaryDnsController.text
                      ]);
                } catch (error) {
                  print(error);
                }
              },
            ),
            RaisedButton(
              child: Text('Disconnect'),
              onPressed: () => FlutterVpn.disconnect(),
            ),
            RaisedButton(
                child: Text('Update State'),
                onPressed: () async {
                  var newState = await FlutterVpn.currentState;
                  setState(() => state = newState);
                }),
            RaisedButton(
                child: Text('Update Charon State'),
                onPressed: () async {
                  var newState = await FlutterVpn.charonErrorState;
                  setState(() => charonState = newState);
                }),
          ],
        ),
      ),
    );
  }
}
