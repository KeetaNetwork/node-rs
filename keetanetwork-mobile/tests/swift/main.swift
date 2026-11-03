import Foundation

func check(_ condition: Bool, _ description: String) {
	if !condition {
		print("FAILED: \(description)")
		exit(1)
	}
	print("ok: \(description)")
}

let webPhrase = Array(repeating: "abandon", count: 23).joined(separator: " ") + " art"
let webPublicKey = "keeta_aabienrwknkyqfrfufv7hyrduri3ctebcu6r4bej6bicpuvhdzpowydjkvcp5ni"
let webSignature = "7ab82fe1039be1c222c309175400334c4c3e26d7ceb345d747758bc760cec61f072be40975f2c79a55081947b6d81cd0ba4e598b26ac1accd4e5ae10406e86b6"
let message = Data("keeta mobile prototype vector".utf8)

let wallet = try MobileWallet.fromPhraseBytes(phrase: Data(webPhrase.utf8))
check(try wallet.publicKey(index: 0) == webPublicKey, "public key matches the web wallet")

let signature = try wallet.sign(index: 0, message: message)
let signatureHex = signature.map { String(format: "%02x", $0) }.joined()
check(signatureHex == webSignature, "signature matches the web wallet")
check(try verifySignature(publicKey: webPublicKey, message: message, signature: signature), "signature verifies")

let generated = try generatePhraseBytes()
let generatedWallet = try MobileWallet.fromPhraseBytes(phrase: generated)
check(try generatedWallet.publicKey(index: 0).hasPrefix("keeta_"), "generated phrase opens a wallet")

do {
	_ = try MobileWallet.fromPhraseBytes(phrase: Data("not a phrase".utf8))
	check(false, "invalid phrase is rejected")
} catch WalletError.InvalidPhrase {
	check(true, "invalid phrase is rejected")
}

var start = Date()
_ = try MobileWallet.fromPhraseBytes(phrase: Data(webPhrase.utf8))
print("wallet open: \(Int(Date().timeIntervalSince(start) * 1000)) ms")
start = Date()
_ = try wallet.sign(index: 0, message: message)
print("sign: \(Int(Date().timeIntervalSince(start) * 1000)) ms")
