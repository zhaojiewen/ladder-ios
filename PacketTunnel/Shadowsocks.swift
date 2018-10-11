//
//  Shadowsocks.swift
//  PacketTunnel
//
//  Created by Aofei Sheng on 2018/3/23.
//  Copyright © 2018 Aofei Sheng. All rights reserved.
//

import CocoaAsyncSocket
import CommonCrypto

class Shadowsocks: NSObject, GCDAsyncSocketDelegate {
	class SOCKS5ProxySocketExtra {
		enum ReadStatus {
			case invalid
			case readingVersionIdentifierAndNumberOfMethods
			case readingMethods
			case readingConnectHeader
			case readingIPv4Address
			case readingDomainLength
			case readingDomain
			case readingIPv6Address
			case readingPort
			case forwarding
		}

		enum WriteStatus {
			case invalid
			case sendingResponse
			case forwarding
		}

		let shadowsocksSocket: GCDAsyncSocket

		var readStatus = ReadStatus.invalid
		var writeStatus = WriteStatus.invalid
		var destinationHost = ""
		var destinationPort = UInt16(0)
		var encryptor: CCCryptorRef?
		var decryptor: CCCryptorRef?

		init(shadowsocksSocket: GCDAsyncSocket) {
			self.shadowsocksSocket = shadowsocksSocket
		}
	}

	let queue = DispatchQueue(label: "Shadowsocks Queue")
	let serverAddress: String
	let serverPort: UInt16
	let localAddress: String
	let localPort: UInt16
	let password: String
	let method: String
	let key: Data
	let ivLength: Int

	var socks5ProxyLocal: GCDAsyncSocket?

	init(serverAddress: String, serverPort: UInt16, localAddress: String, localPort: UInt16, password: String, method: String) {
		self.serverAddress = serverAddress
		self.serverPort = serverPort
		self.localAddress = localAddress
		self.localPort = localPort
		self.password = password
		self.method = method

		var keyLength: Int
		switch method {
		case "AES-128-CFB":
			keyLength = 16
			ivLength = 16
		case "AES-192-CFB":
			keyLength = 24
			ivLength = 16
		case "RC4-MD5":
			keyLength = 16
			ivLength = 16
		default: // AES-256-CFB
			keyLength = 32
			ivLength = 16
		}

		let passwordData = password.data(using: String.Encoding.utf8)!

		var passwordMD5 = Data(count: Int(CC_MD5_DIGEST_LENGTH))
		passwordData.withUnsafeBytes { body in
			_ = passwordMD5.withUnsafeMutableBytes { passwordMD5Body in
				CC_MD5(UnsafeRawPointer(body), CC_LONG(passwordData.count), passwordMD5Body)
			}
		}

		var extendPasswordData = Data(count: passwordData.count + passwordMD5.count)
		extendPasswordData.replaceSubrange(passwordMD5.count ..< extendPasswordData.count, with: passwordData)

		var length = 0
		var result = Data(count: keyLength + ivLength)
		while length < result.count {
			let copyLength = min(result.count - length, passwordMD5.count)
			result.withUnsafeMutableBytes { body in
				passwordMD5.copyBytes(to: body.advanced(by: length), count: copyLength)
			}
			extendPasswordData.replaceSubrange(0 ..< passwordMD5.count, with: passwordMD5)
			extendPasswordData.withUnsafeBytes { body in
				_ = passwordMD5.withUnsafeMutableBytes { passwordMD5Body in
					CC_MD5(UnsafeRawPointer(body), CC_LONG(extendPasswordData.count), passwordMD5Body)
				}
			}
			length += copyLength
		}

		key = result.subdata(in: 0 ..< keyLength)
	}

	func start() throws {
		socks5ProxyLocal = GCDAsyncSocket(delegate: self, delegateQueue: queue, socketQueue: queue)
		try socks5ProxyLocal?.accept(onInterface: localAddress, port: localPort)
	}

	func stop() {
		socks5ProxyLocal?.setDelegate(nil, delegateQueue: nil)
		socks5ProxyLocal?.disconnect()
		socks5ProxyLocal = nil
	}

	func socket(_ sock: GCDAsyncSocket, didAcceptNewSocket newSocket: GCDAsyncSocket) {
		guard sock == socks5ProxyLocal else {
			return
		}

		let socks5ProxySocketExtra = SOCKS5ProxySocketExtra(shadowsocksSocket: GCDAsyncSocket(delegate: self, delegateQueue: queue, socketQueue: queue))
		socks5ProxySocketExtra.shadowsocksSocket.userData = newSocket

		newSocket.setDelegate(self, delegateQueue: queue)
		newSocket.userData = socks5ProxySocketExtra

		socks5ProxySocketExtra.readStatus = .readingVersionIdentifierAndNumberOfMethods
		newSocket.readData(toLength: 2, withTimeout: -1, tag: 0)
	}

	func socket(_ sock: GCDAsyncSocket, didRead data: Data, withTag tag: Int) {
		guard sock != socks5ProxyLocal else {
			return
		}

		switch tag {
		case 0:
			guard let socks5ProxySocketExtra = sock.userData as? SOCKS5ProxySocketExtra else {
				return
			}

			switch socks5ProxySocketExtra.readStatus {
			case .readingVersionIdentifierAndNumberOfMethods:
				data.withUnsafeBytes { (body: UnsafePointer<UInt8>) in
					guard body.pointee == 5, body.successor().pointee > 0 else {
						sock.disconnectAfterWriting()
						return
					}

					socks5ProxySocketExtra.readStatus = .readingMethods
					sock.readData(toLength: UInt(body.successor().pointee), withTimeout: -1, tag: 0)
				}
			case .readingMethods:
				sock.write(Data(bytes: [0x05, 0x00]), withTimeout: -1, tag: 0)

				socks5ProxySocketExtra.readStatus = .readingConnectHeader
				sock.readData(toLength: 4, withTimeout: -1, tag: 0)
			case .readingConnectHeader:
				data.withUnsafeBytes { (body: UnsafePointer<UInt8>) in
					guard body.pointee == 5, body.successor().pointee == 1 else {
						sock.disconnectAfterWriting()
						return
					}

					switch body.advanced(by: 3).pointee {
					case 1:
						socks5ProxySocketExtra.readStatus = .readingIPv4Address
						sock.readData(toLength: 4, withTimeout: -1, tag: 0)
					case 3:
						socks5ProxySocketExtra.readStatus = .readingDomainLength
						sock.readData(toLength: 1, withTimeout: -1, tag: 0)
					case 4:
						socks5ProxySocketExtra.readStatus = .readingIPv6Address
						sock.readData(toLength: 16, withTimeout: -1, tag: 0)
					default:
						break
					}
				}
			case .readingIPv4Address:
				var address = Data(count: Int(INET_ADDRSTRLEN))
				data.withUnsafeBytes { body in
					_ = address.withUnsafeMutableBytes { addressBody in
						inet_ntop(AF_INET, UnsafeRawPointer(body), addressBody, socklen_t(INET_ADDRSTRLEN))
					}
				}
				address.withUnsafeBytes { body in
					socks5ProxySocketExtra.destinationHost = String(cString: body, encoding: .utf8)!
				}

				socks5ProxySocketExtra.readStatus = .readingPort
				sock.readData(toLength: 2, withTimeout: -1, tag: 0)
			case .readingDomainLength:
				data.withUnsafeBytes { (body: UnsafePointer<Int8>) in
					socks5ProxySocketExtra.readStatus = .readingDomain
					sock.readData(toLength: UInt(UnsafeRawPointer(body).load(as: UInt8.self)), withTimeout: -1, tag: 0)
				}
			case .readingDomain:
				socks5ProxySocketExtra.destinationHost = String(data: data, encoding: .utf8)!

				socks5ProxySocketExtra.readStatus = .readingPort
				sock.readData(toLength: 2, withTimeout: -1, tag: 0)
			case .readingIPv6Address:
				var address = Data(count: Int(INET6_ADDRSTRLEN))
				data.withUnsafeBytes { body in
					_ = address.withUnsafeMutableBytes { addressBody in
						inet_ntop(AF_INET6, UnsafeRawPointer(body), addressBody, socklen_t(INET6_ADDRSTRLEN))
					}
				}
				address.withUnsafeBytes { body in
					socks5ProxySocketExtra.destinationHost = String(cString: body, encoding: .utf8)!
				}

				socks5ProxySocketExtra.readStatus = .readingPort
				sock.readData(toLength: 2, withTimeout: -1, tag: 0)
			case .readingPort:
				data.withUnsafeBytes { body in
					socks5ProxySocketExtra.destinationPort = UnsafeRawPointer(body).load(as: UInt16.self).bigEndian
				}

				socks5ProxySocketExtra.readStatus = .forwarding

				do {
					try socks5ProxySocketExtra.shadowsocksSocket.connect(toHost: serverAddress, onPort: serverPort)
				} catch {
					sock.disconnectAfterWriting()
				}
			case .forwarding:
				var data = data
				if let encryptor = socks5ProxySocketExtra.encryptor {
					let dataCount = data.count
					_ = data.withUnsafeMutableBytes { dataBody in
						CCCryptorUpdate(encryptor, dataBody, dataCount, dataBody, dataCount, nil)
					}
				} else {
					let hostLength = socks5ProxySocketExtra.destinationHost.utf8.count
					let length = 1 + 1 + hostLength + 2 + data.count

					var response = Data(count: length)
					response.withUnsafeMutableBytes { (body: UnsafeMutablePointer<UInt8>) in
						body.pointee = 3
						body.successor().pointee = UInt8(hostLength)
					}

					response.replaceSubrange(2 ..< 2 + hostLength, with: socks5ProxySocketExtra.destinationHost.utf8)

					var port = socks5ProxySocketExtra.destinationPort.bigEndian
					withUnsafeBytes(of: &port) { body in
						response.replaceSubrange(2 + hostLength ..< 4 + hostLength, with: body)
					}

					response.replaceSubrange(4 + hostLength ..< length, with: data)

					var writeIV = Data(count: ivLength)
					_ = writeIV.withUnsafeMutableBytes { body in
						SecRandomCopyBytes(kSecRandomDefault, ivLength, body)
					}

					var encryptor: CCCryptorRef
					switch method {
					case "RC4-MD5":
						var combinedKey = Data(capacity: key.count + ivLength)
						combinedKey.append(key)
						combinedKey.append(writeIV)
						let cryptor = UnsafeMutablePointer<CCCryptorRef?>.allocate(capacity: 1)
						_ = combinedKey.withUnsafeBytes { combinedKeyBody in
							CCCryptorCreateWithMode(CCOperation(kCCEncrypt), CCMode(kCCModeRC4), CCAlgorithm(kCCAlgorithmRC4), CCPadding(ccNoPadding), nil, UnsafeRawPointer(combinedKeyBody), combinedKey.count, nil, 0, 0, 0, cryptor)
						}
						encryptor = cryptor.pointee!
					default: // AES-128-CFB, AES-192-CFB, AES-256-CFB
						let cryptor = UnsafeMutablePointer<CCCryptorRef?>.allocate(capacity: 1)
						_ = key.withUnsafeBytes { keyBody in
							writeIV.withUnsafeBytes { writeIVBody in
								CCCryptorCreateWithMode(CCOperation(kCCEncrypt), CCMode(kCCModeCFB), CCAlgorithm(kCCAlgorithmAES), CCPadding(ccNoPadding), UnsafeRawPointer(writeIVBody), UnsafeRawPointer(keyBody), key.count, nil, 0, 0, 0, cryptor)
							}
						}
						encryptor = cryptor.pointee!
					}

					socks5ProxySocketExtra.encryptor = encryptor

					let responseCount = response.count
					_ = response.withUnsafeMutableBytes { responseBody in
						CCCryptorUpdate(encryptor, responseBody, responseCount, responseBody, responseCount, nil)
					}

					data = Data(capacity: writeIV.count + response.count)
					data.append(writeIV)
					data.append(response)
				}

				socks5ProxySocketExtra.shadowsocksSocket.write(data, withTimeout: -1, tag: 1)
			default:
				break
			}
		case 1:
			guard let socks5ProxySocket = sock.userData as? GCDAsyncSocket, let socks5ProxySocketExtra = socks5ProxySocket.userData as? SOCKS5ProxySocketExtra else {
				return
			}

			var data = data
			if socks5ProxySocketExtra.decryptor == nil {
				if data.count < ivLength {
					socks5ProxySocket.write(data, withTimeout: -1, tag: 0)
					return
				}

				let readIV = data.subdata(in: 0 ..< ivLength)
				switch method {
				case "RC4-MD5":
					var combinedKey = Data(capacity: key.count + ivLength)
					combinedKey.append(key)
					combinedKey.append(readIV)
					let cryptor = UnsafeMutablePointer<CCCryptorRef?>.allocate(capacity: 1)
					_ = combinedKey.withUnsafeBytes { combinedKeyBody in
						CCCryptorCreateWithMode(CCOperation(kCCDecrypt), CCMode(kCCModeRC4), CCAlgorithm(kCCAlgorithmRC4), CCPadding(ccNoPadding), nil, UnsafeRawPointer(combinedKeyBody), combinedKey.count, nil, 0, 0, 0, cryptor)
					}
					socks5ProxySocketExtra.decryptor = cryptor.pointee
				default: // AES-128-CFB, AES-192-CFB, AES-256-CFB
					let cryptor = UnsafeMutablePointer<CCCryptorRef?>.allocate(capacity: 1)
					_ = key.withUnsafeBytes { keyBody in
						readIV.withUnsafeBytes { readIVBody in
							CCCryptorCreateWithMode(CCOperation(kCCDecrypt), CCMode(kCCModeCFB), CCAlgorithm(kCCAlgorithmAES), CCPadding(ccNoPadding), UnsafeRawPointer(readIVBody), UnsafeRawPointer(keyBody), key.count, nil, 0, 0, 0, cryptor)
						}
					}
					socks5ProxySocketExtra.decryptor = cryptor.pointee
				}

				data = data.subdata(in: ivLength ..< data.count)
			}

			guard let decryptor = socks5ProxySocketExtra.decryptor else {
				return
			}

			let dataCount = data.count
			_ = data.withUnsafeMutableBytes { dataBody in
				CCCryptorUpdate(decryptor, dataBody, dataCount, dataBody, dataCount, nil)
			}

			socks5ProxySocket.write(data, withTimeout: -1, tag: 0)
		default:
			break
		}
	}

	func socket(_ sock: GCDAsyncSocket, didConnectToHost host: String, port: UInt16) {
		guard sock != socks5ProxyLocal, host == serverAddress, port == serverPort, let socks5ProxySocket = sock.userData as? GCDAsyncSocket, let socks5ProxySocketExtra = socks5ProxySocket.userData as? SOCKS5ProxySocketExtra else {
			return
		}

		socks5ProxySocketExtra.writeStatus = .sendingResponse
		socks5ProxySocket.write(Data(bytes: [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), withTimeout: -1, tag: 0)
	}

	func socket(_ sock: GCDAsyncSocket, didWriteDataWithTag tag: Int) {
		guard sock != socks5ProxyLocal else {
			return
		}

		switch tag {
		case 0:
			guard let socks5ProxySocketExtra = sock.userData as? SOCKS5ProxySocketExtra else {
				return
			}

			switch socks5ProxySocketExtra.writeStatus {
			case .sendingResponse:
				socks5ProxySocketExtra.writeStatus = .forwarding
				sock.readData(withTimeout: -1, tag: 0)

				socks5ProxySocketExtra.shadowsocksSocket.readData(withTimeout: -1, tag: 1)
			case .forwarding:
				socks5ProxySocketExtra.shadowsocksSocket.readData(withTimeout: -1, tag: 1)
			default:
				break
			}
		case 1:
			guard let socks5ProxyScoket = sock.userData as? GCDAsyncSocket else {
				return
			}

			socks5ProxyScoket.readData(withTimeout: -1, tag: 0)
		default:
			break
		}
	}

	func socketDidDisconnect(_ sock: GCDAsyncSocket, withError _: Error?) {
		guard sock != socks5ProxyLocal else {
			return
		}

		if let socks5ProxyScoket = sock.userData as? GCDAsyncSocket, socks5ProxyScoket.isConnected {
			socks5ProxyScoket.disconnectAfterWriting()
		}

		if let socks5ProxySocketExtra = sock.userData as? SOCKS5ProxySocketExtra, socks5ProxySocketExtra.shadowsocksSocket.isConnected {
			socks5ProxySocketExtra.shadowsocksSocket.disconnectAfterWriting()
		}
	}
}
