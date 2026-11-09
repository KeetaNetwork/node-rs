import Foundation

struct Fixture: Decodable {
	let message: String
	let vectors: [Vector]
}

struct Vector: Decodable {
	let phrase: String
	let accounts: [AccountVector]
}

struct AccountVector: Decodable {
	let index: UInt32
	let publicKey: String
	let signature: String
	let ciphertext: String
}

func check(_ condition: Bool, _ description: String) {
	if !condition {
		print("FAILED: \(description)")
		exit(1)
	}
	print("ok: \(description)")
}

func bytes(hex: String) -> Data {
	var data = Data()
	var position = hex.startIndex
	while position < hex.endIndex {
		let next = hex.index(position, offsetBy: 2)
		data.append(UInt8(hex[position..<next], radix: 16)!)
		position = next
	}
	return data
}

let fixturePath = CommandLine.arguments[1]
let fixture = try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: URL(fileURLWithPath: fixturePath)))
let message = bytes(hex: fixture.message)

for (vectorIndex, vector) in fixture.vectors.enumerated() {
	let wallet = try MobileWallet.fromPhraseBytes(phrase: Data(vector.phrase.utf8))
	for account in vector.accounts {
		let name = "vector \(vectorIndex) account \(account.index)"
		let webSignature = bytes(hex: account.signature)
		check(try wallet.publicKey(index: account.index) == account.publicKey, "\(name) public key matches the web wallet")
		check(try wallet.sign(index: account.index, message: message) == webSignature, "\(name) signature matches the web wallet")
		check(try verifySignature(publicKey: account.publicKey, message: message, signature: webSignature), "\(name) signature verifies")
		check(try wallet.decrypt(index: account.index, ciphertext: bytes(hex: account.ciphertext)) == message, "\(name) web ciphertext decrypts")
	}
}

let generated = try generatePhraseBytes()
let generatedWallet = try MobileWallet.fromPhraseBytes(phrase: generated)
check(try generatedWallet.publicKey(index: 0).hasPrefix("keeta_"), "generated phrase opens a wallet")

let firstVector = fixture.vectors[0]
let draft = PhraseDraft()
for (index, word) in firstVector.phrase.split(separator: " ").enumerated() {
	try draft.setWord(index: UInt32(index), word: Data(word.utf8))
}
check(draft.status() == .valid, "draft reports a valid phrase")
check(try draft.openWallet().publicKey(index: 0) == firstVector.accounts[0].publicKey, "draft opens the web wallet")

do {
	_ = try MobileWallet.fromPhraseBytes(phrase: Data("not a phrase".utf8))
	check(false, "invalid phrase is rejected")
} catch WalletError.InvalidPhrase {
	check(true, "invalid phrase is rejected")
}
