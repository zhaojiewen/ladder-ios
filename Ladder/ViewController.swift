//
//  ViewController.swift
//  Ladder
//
//  Created by Aofei Sheng on 2018/3/23.
//  Copyright © 2018 Aofei Sheng. All rights reserved.
//

import Eureka
import NetworkExtension
import SafariServices

class ViewController: FormViewController {
	override func viewDidLoad() {
		super.viewDidLoad()

		navigationItem.title = NSLocalizedString("Ladder", comment: "")
		navigationItem.rightBarButtonItem = UIBarButtonItem(image: #imageLiteral(resourceName: "Icons/Info"), style: .plain, target: self, action: #selector(openPost))
		navigationController?.navigationBar.barStyle = .black
		navigationController?.navigationBar.tintColor = .white
		navigationController?.navigationBar.barTintColor = UIColor(red: 80 / 255, green: 140 / 255, blue: 240 / 255, alpha: 1)
		navigationController?.navigationBar.titleTextAttributes = [NSAttributedString.Key.foregroundColor: UIColor.white]

		let tapToDismissKeyboard = UITapGestureRecognizer(target: view, action: #selector(UIView.endEditing))
		tapToDismissKeyboard.cancelsTouchesInView = false
		view.addGestureRecognizer(tapToDismissKeyboard)

		form
			+++ Section(header: NSLocalizedString("General", comment: ""), footer: "") { section in
				section.tag = "General"
				section.header?.height = { 30 }
				section.footer?.height = { .leastNonzeroMagnitude }
			}
			<<< SwitchRow { row in
				row.tag = "General - Hide VPN Icon"
				row.title = NSLocalizedString("Hide VPN Icon", comment: "")
				if let data = ReadFromKeychain(key: "general_hide_vpn_icon") {
					row.value = String(data: data, encoding: .utf8) == "true"
				} else {
					row.value = false
				}
			}
			<<< URLRow { row in
				row.tag = "General - PAC URL"
				row.title = "PAC URL"
				row.placeholder = NSLocalizedString("Enter PAC URL here", comment: "")
				if let data = ReadFromKeychain(key: "general_pac_url") {
					row.value = URL(string: String(data: data, encoding: .utf8)!)
				} else {
					row.value = URL(string: "https://git.io/gfwpac")
				}

				row.add(rule: RuleRequired(msg: NSLocalizedString("Please enter a PAC URL.", comment: "")))
				row.add(rule: RuleURL(allowsEmpty: false, requiresProtocol: true, msg: NSLocalizedString("Please enter a valid PAC URL.", comment: "")))
			}
			<<< IntRow { row in
				row.tag = "General - PAC Max Age"
				row.title = NSLocalizedString("PAC Max Age", comment: "")
				row.placeholder = NSLocalizedString("Enter PAC max age here", comment: "")
				if let data = ReadFromKeychain(key: "general_pac_max_age") {
					row.value = Int(String(data: data, encoding: .utf8)!)
				} else {
					row.value = 3600
				}

				row.formatter = NumberFormatter()

				row.add(rule: RuleRequired(msg: NSLocalizedString("Please enter a PAC max age.", comment: "")))
				row.add(rule: RuleGreaterOrEqualThan(min: 0, msg: NSLocalizedString("PAC max age must greater than or equal to 0.", comment: "")))
				row.add(rule: RuleSmallerOrEqualThan(max: 86400, msg: NSLocalizedString("PAC max age must smaller than or equal to 86400.", comment: "")))
			}

			+++ Section(header: NSLocalizedString("Shadowsocks", comment: ""), footer: "") { section in
				section.tag = "Shadowsocks"
				section.header?.height = { 30 }
				section.footer?.height = { .leastNonzeroMagnitude }
			}
			<<< TextRow { row in
				row.tag = "Shadowsocks - Server Address"
				row.title = NSLocalizedString("Server Address", comment: "")
				row.placeholder = NSLocalizedString("Enter server address here", comment: "")
				if let data = ReadFromKeychain(key: "shadowsocks_server_address") {
					row.value = String(data: data, encoding: .utf8)
				}

				row.cell.textField.keyboardType = .asciiCapable
				row.cell.textField.autocapitalizationType = .none

				row.add(rule: RuleRequired(msg: NSLocalizedString("Please enter a Shadowsocks server address.", comment: "")))
			}
			<<< IntRow { row in
				row.tag = "Shadowsocks - Server Port"
				row.title = NSLocalizedString("Server Port", comment: "")
				row.placeholder = NSLocalizedString("Enter server port here", comment: "")
				if let data = ReadFromKeychain(key: "shadowsocks_server_port"), let string = String(data: data, encoding: .utf8) {
					row.value = Int(string)
				}

				row.formatter = NumberFormatter()

				row.add(rule: RuleRequired(msg: NSLocalizedString("Please enter a Shadowsocks server port.", comment: "")))
				row.add(rule: RuleGreaterOrEqualThan(min: 0, msg: NSLocalizedString("Shadowsocks server port must greater than or equal to 0.", comment: "")))
				row.add(rule: RuleSmallerOrEqualThan(max: 65535, msg: NSLocalizedString("Shadowsocks server port must smaller than or equal to 65535.", comment: "")))
			}
			<<< TextRow { row in
				row.tag = "Shadowsocks - Local Address"
				row.title = NSLocalizedString("Local Address", comment: "")
				row.placeholder = NSLocalizedString("Enter local address here", comment: "")
				if let data = ReadFromKeychain(key: "shadowsocks_local_address") {
					row.value = String(data: data, encoding: .utf8)
				} else {
					row.value = "127.0.0.1"
				}

				row.cell.textField.keyboardType = .asciiCapable
				row.cell.textField.autocapitalizationType = .none

				row.add(rule: RuleRequired(msg: NSLocalizedString("Please enter a Shadowsocks local address.", comment: "")))
			}
			<<< IntRow { row in
				row.tag = "Shadowsocks - Local Port"
				row.title = NSLocalizedString("Local Port", comment: "")
				row.placeholder = NSLocalizedString("Enter local port here", comment: "")
				if let data = ReadFromKeychain(key: "shadowsocks_local_port") {
					row.value = Int(String(data: data, encoding: .utf8)!)
				} else {
					row.value = 1081
				}

				row.formatter = NumberFormatter()

				row.add(rule: RuleRequired(msg: NSLocalizedString("Please enter a Shadowsocks local port.", comment: "")))
				row.add(rule: RuleGreaterOrEqualThan(min: 0, msg: NSLocalizedString("Shadowsocks local port must greater than or equal to 0.", comment: "")))
				row.add(rule: RuleSmallerOrEqualThan(max: 65535, msg: NSLocalizedString("Shadowsocks local port must smaller than or equal to 65535.", comment: "")))
			}
			<<< PasswordRow { row in
				row.tag = "Shadowsocks - Password"
				row.title = NSLocalizedString("Password", comment: "")
				row.placeholder = NSLocalizedString("Enter password here", comment: "")
				if let data = ReadFromKeychain(key: "shadowsocks_password") {
					row.value = String(data: data, encoding: .utf8)
				}

				row.add(rule: RuleRequired(msg: NSLocalizedString("Please enter a Shadowsocks password.", comment: "")))
			}
			<<< ActionSheetRow<String> { row in
				row.tag = "Shadowsocks - Method"
				row.title = NSLocalizedString("Method", comment: "")
				row.selectorTitle = NSLocalizedString("Shadowsocks Method", comment: "")
				row.options = ["AES-128-CFB", "AES-192-CFB", "AES-256-CFB", "RC4-MD5"]
				if let data = ReadFromKeychain(key: "shadowsocks_method") {
					row.value = String(data: data, encoding: .utf8)
				} else {
					row.value = "AES-256-CFB"
				}

				row.cell.detailTextLabel?.textColor = .black
			}

			+++ Section(header: "", footer: "") { section in
				section.tag = "Configure"
				section.header?.height = { 30 }
				section.footer?.height = { .leastNonzeroMagnitude }
			}
			<<< ButtonRow { row in
				row.tag = "Configure - Configure"
				row.title = NSLocalizedString("Configure", comment: "")
			}.onCellSelection { _, _ in
				let configuringAlertController = UIAlertController(
					title: NSLocalizedString("Configuring...", comment: ""),
					message: nil,
					preferredStyle: .alert
				)
				self.present(configuringAlertController, animated: true)

				if let firstValidationError = self.form.validate().first {
					let alertController = UIAlertController(
						title: NSLocalizedString("Configuration Failed", comment: ""),
						message: firstValidationError.msg,
						preferredStyle: .alert
					)
					alertController.addAction(UIAlertAction(title: NSLocalizedString("OK", comment: ""), style: .default))
					configuringAlertController.dismiss(animated: true) {
						self.present(alertController, animated: true)
					}

					return
				}

				let generalHideVPNIcon = (self.form.rowBy(tag: "General - Hide VPN Icon") as! SwitchRow).value!
				let generalPACURL = (self.form.rowBy(tag: "General - PAC URL") as! URLRow).value!
				let generalPACMaxAge = (self.form.rowBy(tag: "General - PAC Max Age") as! IntRow).value!
				let shadowsocksServerAddress = (self.form.rowBy(tag: "Shadowsocks - Server Address") as! TextRow).value!
				let shadowsocksServerPort = (self.form.rowBy(tag: "Shadowsocks - Server Port") as! IntRow).value!
				let shadowsocksLocalAddress = (self.form.rowBy(tag: "Shadowsocks - Local Address") as! TextRow).value!
				let shadowsocksLocalPort = (self.form.rowBy(tag: "Shadowsocks - Local Port") as! IntRow).value!
				let shadowsocksPassword = (self.form.rowBy(tag: "Shadowsocks - Password") as! PasswordRow).value!
				let shadowsocksMethod = (self.form.rowBy(tag: "Shadowsocks - Method") as! ActionSheetRow<String>).value!

				URLSession.shared.dataTask(with: generalPACURL) { data, response, _ in
					guard (response as? HTTPURLResponse)?.statusCode == 200, let data = data, let pacContent = String(data: data, encoding: .utf8) else {
						let alertController = UIAlertController(
							title: NSLocalizedString("Configuration Failed", comment: ""),
							message: NSLocalizedString("Unable to download data from the PAC URL.", comment: ""),
							preferredStyle: .alert
						)
						alertController.addAction(UIAlertAction(title: NSLocalizedString("OK", comment: ""), style: .default))
						configuringAlertController.dismiss(animated: true) {
							self.present(alertController, animated: true)
						}

						return
					}

					NETunnelProviderManager.loadAllFromPreferences { providerManagers, _ in
						var providerManager = NETunnelProviderManager()
						if let providerManagers = providerManagers, providerManagers.count > 0 {
							providerManager = providerManagers[0]
							if providerManagers.count > 1 {
								for providerManager in providerManagers[1...] {
									providerManager.removeFromPreferences()
								}
							}
						}

						let providerConfiguration = NETunnelProviderProtocol()
						providerConfiguration.serverAddress = shadowsocksServerAddress
						providerConfiguration.providerConfiguration = [
							"general_hide_vpn_icon": generalHideVPNIcon,
							"general_pac_url": generalPACURL.absoluteString,
							"general_pac_content": pacContent,
							"general_pac_max_age": TimeInterval(generalPACMaxAge),
							"shadowsocks_server_address": shadowsocksServerAddress,
							"shadowsocks_server_port": UInt16(shadowsocksServerPort),
							"shadowsocks_local_address": shadowsocksLocalAddress,
							"shadowsocks_local_port": UInt16(shadowsocksLocalPort),
							"shadowsocks_password": shadowsocksPassword,
							"shadowsocks_method": shadowsocksMethod,
						]

						providerManager.localizedDescription = NSLocalizedString("Ladder", comment: "")
						providerManager.protocolConfiguration = providerConfiguration
						providerManager.isEnabled = true
						providerManager.saveToPreferences { error in
							if error == nil {
								self.WriteToKeychain(key: "general_hide_vpn_icon", data: (generalHideVPNIcon ? "true" : "false").data(using: .utf8))
								self.WriteToKeychain(key: "general_pac_url", data: generalPACURL.absoluteString.data(using: .utf8))
								self.WriteToKeychain(key: "general_pac_max_age", data: String(generalPACMaxAge).data(using: .utf8))
								self.WriteToKeychain(key: "shadowsocks_server_address", data: shadowsocksServerAddress.data(using: .utf8))
								self.WriteToKeychain(key: "shadowsocks_server_port", data: String(shadowsocksServerPort).data(using: .utf8))
								self.WriteToKeychain(key: "shadowsocks_local_address", data: shadowsocksLocalAddress.data(using: .utf8))
								self.WriteToKeychain(key: "shadowsocks_local_port", data: String(shadowsocksLocalPort).data(using: .utf8))
								self.WriteToKeychain(key: "shadowsocks_password", data: shadowsocksPassword.data(using: .utf8))
								self.WriteToKeychain(key: "shadowsocks_method", data: shadowsocksMethod.data(using: .utf8))
								providerManager.loadFromPreferences { error in
									if error == nil {
										providerManager.connection.stopVPNTunnel()
										DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
											try? providerManager.connection.startVPNTunnel()
										}
									}
								}
							}

							configuringAlertController.dismiss(animated: true) {
								let alertController = UIAlertController(title: nil, message: nil, preferredStyle: .alert)
								if error != nil {
									alertController.title = NSLocalizedString("Configuration Failed", comment: "")
									alertController.message = NSLocalizedString("Please try again.", comment: "")
									alertController.addAction(UIAlertAction(title: NSLocalizedString("OK", comment: ""), style: .default))
								} else {
									alertController.title = NSLocalizedString("Configured!", comment: "")
								}

								self.present(alertController, animated: true) {
									if error == nil {
										DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
											alertController.dismiss(animated: true)
										}
									}
								}
							}
						}
					}
				}.resume()
			}
	}

	@objc func openPost() {
		present(SFSafariViewController(url: URL(string: "https://aofei.sheng.ws/posts/2018-04-05-immersive-wallless-experience")!), animated: true)
	}

	func ReadFromKeychain(key: String) -> Data? {
		var query = [CFString: Any]()
		query[kSecClass] = kSecClassGenericPassword
		query[kSecAttrAccount] = key
		query[kSecMatchLimit] = kSecMatchLimitOne
		query[kSecReturnData] = kCFBooleanTrue

		var data: CFTypeRef?
		SecItemCopyMatching(query as CFDictionary, &data)

		return data as? Data
	}

	@discardableResult
	func WriteToKeychain(key: String, data: Data?) -> Bool {
		var query = [CFString: Any]()
		query[kSecClass] = kSecClassGenericPassword
		query[kSecAttrAccount] = key
		query[kSecValueData] = data
		SecItemDelete(query as CFDictionary)
		return data != nil ? SecItemAdd(query as CFDictionary, nil) == noErr : true
	}
}
