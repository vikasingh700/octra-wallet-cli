import * as crypto from "crypto";
import * as fs from "fs";
import * as nacl from "tweetnacl";
import * as bip39 from "bip39";
import { Command } from "commander";
import readline from "readline";

interface MasterKey {
  masterPrivateKey: Buffer;
  masterChainCode: Buffer;
}

interface ChildKey {
  childPrivateKey: Buffer;
  childChainCode: Buffer;
}

interface DerivedPath {
  key: Buffer;
  chain: Buffer;
}

interface NetworkDerivation {
  privateKey: Buffer;
  chainCode: Buffer;
  publicKey: Buffer;
  address: string;
  path: number[];
  networkTypeName: string;
  network: number;
  contract: number;
  account: number;
  index: number;
}

const BASE58_ALPHABET: string =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Helper functions
function bufferToHex(buffer: Buffer | Uint8Array): string {
  return Buffer.from(buffer).toString("hex");
}

function base64Encode(buffer: Buffer | Uint8Array): string {
  return Buffer.from(buffer).toString("base64");
}

function base58Encode(buffer: Buffer): string {
  if (buffer.length === 0) return "";

  let num: bigint = BigInt("0x" + buffer.toString("hex"));
  let encoded: string = "";

  while (num > 0n) {
    const remainder: bigint = num % 58n;
    num = num / 58n;
    encoded = BASE58_ALPHABET[Number(remainder)] + encoded;
  }

  for (let i = 0; i < buffer.length && buffer[i] === 0; i++) {
    encoded = "1" + encoded;
  }

  return encoded;
}

function generateEntropy(strength: number = 128): Buffer {
  if (![128, 160, 192, 224, 256].includes(strength)) {
    throw new Error("Strength must be 128, 160, 192, 224 or 256 bits");
  }
  return crypto.randomBytes(strength / 8);
}

function deriveMasterKey(seed: Buffer): MasterKey {
  const key: Buffer = Buffer.from("Octra seed", "utf8");
  const mac: Buffer = crypto.createHmac("sha512", key).update(seed).digest();

  const masterPrivateKey: Buffer = mac.slice(0, 32);
  const masterChainCode: Buffer = mac.slice(32, 64);

  return { masterPrivateKey, masterChainCode };
}

function deriveChildKeyEd25519(
  privateKey: Buffer,
  chainCode: Buffer,
  index: number
): ChildKey {
  let data: Buffer;

  if (index >= 0x80000000) {
    data = Buffer.concat([
      Buffer.from([0x00]),
      privateKey,
      Buffer.from([
        (index >>> 24) & 0xff,
        (index >>> 16) & 0xff,
        (index >>> 8) & 0xff,
        index & 0xff,
      ]),
    ]);
  } else {
    const keyPair = nacl.sign.keyPair.fromSeed(privateKey);
    const publicKey: Buffer = Buffer.from(keyPair.publicKey);
    data = Buffer.concat([
      publicKey,
      Buffer.from([
        (index >>> 24) & 0xff,
        (index >>> 16) & 0xff,
        (index >>> 8) & 0xff,
        index & 0xff,
      ]),
    ]);
  }

  const mac: Buffer = crypto.createHmac("sha512", chainCode).update(data).digest();
  const childPrivateKey: Buffer = mac.slice(0, 32);
  const childChainCode: Buffer = mac.slice(32, 64);

  return { childPrivateKey, childChainCode };
}

function derivePath(seed: Buffer, path: number[]): DerivedPath {
  const { masterPrivateKey, masterChainCode }: MasterKey = deriveMasterKey(seed);
  let key: Buffer = masterPrivateKey;
  let chain: Buffer = masterChainCode;

  for (const index of path) {
    const derived: ChildKey = deriveChildKeyEd25519(key, chain, index);
    key = derived.childPrivateKey;
    chain = derived.childChainCode;
  }

  return { key, chain };
}

function getNetworkTypeName(networkType: number): string {
  switch (networkType) {
    case 0:
      return "MainCoin";
    case 1:
      return `SubCoin ${networkType}`;
    case 2:
      return `Contract ${networkType}`;
    case 3:
      return `Subnet ${networkType}`;
    case 4:
      return `Account ${networkType}`;
    default:
      return `Unknown ${networkType}`;
  }
}

function deriveForNetwork(
  seed: Buffer,
  networkType: number = 0,
  network: number = 0,
  contract: number = 0,
  account: number = 0,
  index: number = 0,
  token: number = 0,
  subnet: number = 0
): NetworkDerivation {
  const coinType: number = networkType === 0 ? 0 : networkType;

  const basePath: number[] = [
    0x80000000 + 345, // Purpose
    0x80000000 + coinType, // Coin type
    0x80000000 + network, // Network
  ];

  const contractPath: number[] = [0x80000000 + contract, 0x80000000 + account];
  const optionalPath: number[] = [0x80000000 + token, 0x80000000 + subnet];
  const finalPath: number[] = [index];

  const fullPath: number[] = [...basePath, ...contractPath, ...optionalPath, ...finalPath];

  const { key: derivedKey, chain: derivedChain }: DerivedPath = derivePath(seed, fullPath);

  const keyPair = nacl.sign.keyPair.fromSeed(derivedKey);
  const derivedAddress: string = createOctraAddress(Buffer.from(keyPair.publicKey));

  return {
    privateKey: derivedKey,
    chainCode: derivedChain,
    publicKey: Buffer.from(keyPair.publicKey),
    address: derivedAddress,
    path: fullPath,
    networkTypeName: getNetworkTypeName(networkType),
    network,
    contract,
    account,
    index,
  };
}

function createOctraAddress(publicKey: Buffer): string {
  const hash: Buffer = crypto.createHash("sha256").update(publicKey).digest();
  const base58Hash: string = base58Encode(hash);
  return "oct" + base58Hash;
}

function verifyAddressFormat(address: string): boolean {
  if (!address.startsWith("oct")) return false;
  if (address.length !== 47) return false;

  const base58Part: string = address.slice(3);
  for (const char of base58Part) {
    if (!BASE58_ALPHABET.includes(char)) return false;
  }

  return true;
}

// CLI functions
async function generateWallet(save: boolean) {
  const entropy = generateEntropy(128);

  const mnemonic = bip39.entropyToMnemonic(entropy.toString("hex"));
  const mnemonicWords = mnemonic.split(" ");
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  const { masterPrivateKey, masterChainCode } = deriveMasterKey(seed);
  const keyPair = nacl.sign.keyPair.fromSeed(masterPrivateKey);
  const privateKeyRaw = Buffer.from(keyPair.secretKey.slice(0, 32));
  const publicKeyRaw = Buffer.from(keyPair.publicKey);
  const address = createOctraAddress(publicKeyRaw);
  if (!verifyAddressFormat(address)) {
    console.error("ERROR: Invalid address format generated");
    return;
  }
  const testMessage = '{"from":"test","to":"test","amount":"1000000","nonce":1}';
  const messageBytes = Buffer.from(testMessage, "utf8");
  const signature = nacl.sign.detached(messageBytes, keyPair.secretKey);
  const signatureB64 = base64Encode(signature);
  let signatureValid = false;
  try {
    signatureValid = nacl.sign.detached.verify(messageBytes, signature, keyPair.publicKey);
  } catch (error) {
    console.log("Signature test failed");
  }

  const walletData = {
    mnemonic: mnemonicWords,
    seed_hex: bufferToHex(seed),
    master_chain_hex: bufferToHex(masterChainCode),
    private_key_hex: bufferToHex(privateKeyRaw),
    public_key_hex: bufferToHex(publicKeyRaw),
    private_key_b64: base64Encode(privateKeyRaw),
    public_key_b64: base64Encode(publicKeyRaw),
    address: address,
    entropy_hex: bufferToHex(entropy),
    test_message: testMessage,
    test_signature: signatureB64,
    signature_valid: signatureValid,
  };

  console.log("\n=== Wallet Details ===");
  console.log(`Mnemonic: ${walletData.mnemonic.join(" ")}`);
  console.log(`Private Key (Hex): ${walletData.private_key_hex}`);
  console.log(`Private Key (B64): ${walletData.private_key_b64}`);
  console.log(`Public Key (Hex): ${walletData.public_key_hex}`);
  console.log(`Public Key (B64): ${walletData.public_key_b64}`);
  console.log(`Address: ${walletData.address}`);
  console.log(`Entropy: ${walletData.entropy_hex}`);
  console.log(`Seed: ${walletData.seed_hex.substring(0, 64)}...`);
  console.log(`Master Chain: ${walletData.master_chain_hex}`);
  console.log(`Test Message: ${walletData.test_message}`);
  console.log(`Test Signature: ${walletData.test_signature}`);
  console.log(`Signature Valid: ${walletData.signature_valid ? "Yes" : "No"}`);

  if (save) {
    const timestamp = Math.floor(Date.now() / 1000);
    const filename = `octra_wallet_${walletData.address.slice(-8)}_${timestamp}.txt`;
    const content = `OCTRA WALLET\n${"=".repeat(50)}\n\nSECURITY WARNING: KEEP THIS FILE SECURE AND NEVER SHARE YOUR PRIVATE KEY\n\nGenerated: ${new Date()
      .toISOString()
      .replace("T", " ")
      .slice(0, 19)}\nAddress Format: oct + Base58(SHA256(pubkey))\n\nMnemonic: ${walletData.mnemonic.join(
      " "
    )}\nPrivate Key (B64): ${walletData.private_key_b64}\nPublic Key (B64): ${walletData.public_key_b64}\nAddress: ${
      walletData.address
    }\n\nTechnical Details:\nEntropy: ${walletData.entropy_hex}\nSignature Algorithm: Ed25519\nDerivation: BIP39-compatible (PBKDF2-HMAC-SHA512, 2048 iterations)\n`;
    fs.writeFileSync(filename, content);
    console.log(`\nWallet saved to: ${filename}`);
  } else {
    console.log("\nTo save the wallet, use the --save option");
  }
}

async function generateMultipleWallets() {
  // Ask user how many wallets to generate
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  function askQuestion(query: string): Promise<string> {
    return new Promise((resolve) => rl.question(query, resolve));
  }

  let count: number;
  while (true) {
    const input = await askQuestion("How many wallets would you like to generate? ");
    count = parseInt(input);
    if (!isNaN(count) && count > 0) break;
    console.log("Please enter a valid positive number.");
  }

  // Generate wallets and accumulate details and addresses
  const allWalletData: any[] = [];
  const allAddresses: string[] = [];
  const timestamp = Math.floor(Date.now() / 1000);
  const walletDetailsFilename = `octra_wallets_${count}_${timestamp}.txt`;
  const addressesFilename = `octra_wallets_addresses_${count}_${timestamp}.txt`;

  for (let i = 0; i < count; i++) {
    const entropy = generateEntropy(128);
    const mnemonic = bip39.entropyToMnemonic(entropy.toString("hex"));
    const mnemonicWords = mnemonic.split(" ");
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    const { masterPrivateKey, masterChainCode } = deriveMasterKey(seed);
    const keyPair = nacl.sign.keyPair.fromSeed(masterPrivateKey);
    const privateKeyRaw = Buffer.from(keyPair.secretKey.slice(0, 32));
    const publicKeyRaw = Buffer.from(keyPair.publicKey);
    const address = createOctraAddress(publicKeyRaw);
    if (!verifyAddressFormat(address)) {
      console.error(`ERROR: Invalid address format generated for wallet #${i + 1}`);
      continue;
    }
    const testMessage = '{"from":"test","to":"test","amount":"1000000","nonce":1}';
    const messageBytes = Buffer.from(testMessage, "utf8");
    const signature = nacl.sign.detached(messageBytes, keyPair.secretKey);
    const signatureB64 = base64Encode(signature);
    let signatureValid = false;
    try {
      signatureValid = nacl.sign.detached.verify(messageBytes, signature, keyPair.publicKey);
    } catch (error) {
      console.log(`Signature test failed for wallet #${i + 1}`);
    }

    const walletData = {
      index: i + 1,
      mnemonic: mnemonicWords,
      seed_hex: bufferToHex(seed),
      master_chain_hex: bufferToHex(masterChainCode),
      private_key_hex: bufferToHex(privateKeyRaw),
      public_key_hex: bufferToHex(publicKeyRaw),
      private_key_b64: base64Encode(privateKeyRaw),
      public_key_b64: base64Encode(publicKeyRaw),
      address: address,
      entropy_hex: bufferToHex(entropy),
      test_message: testMessage,
      test_signature: signatureB64,
      signature_valid: signatureValid,
    };

    allWalletData.push(walletData);
    allAddresses.push(address);
    console.log(`Generated wallet #${i + 1}: ${address}`);
  }

  // Write all details into one file
  let detailsContent =
    `OCTRA WALLETS BATCH\n${"=".repeat(60)}\nGenerated: ${new Date()
      .toISOString()
      .replace("T", " ")
      .slice(0, 19)}\n\nSECURITY WARNING: KEEP THIS FILE SECURE AND NEVER SHARE YOUR PRIVATE KEYS\n\nTotal wallets: ${allWalletData.length}\n\n`;

  for (const wd of allWalletData) {
    detailsContent +=
      `${"-".repeat(60)}\nWallet #${wd.index}\nMnemonic: ${wd.mnemonic.join(" ")}\nPrivate Key (Hex): ${wd.private_key_hex}\nPrivate Key (B64): ${wd.private_key_b64}\nPublic Key (Hex): ${wd.public_key_hex}\nPublic Key (B64): ${wd.public_key_b64}\nAddress: ${wd.address}\nEntropy: ${wd.entropy_hex}\nSeed: ${wd.seed_hex.substring(0, 64)}...\nMaster Chain: ${wd.master_chain_hex}\nTest Message: ${wd.test_message}\nTest Signature: ${wd.test_signature}\nSignature Valid: ${wd.signature_valid ? "Yes" : "No"}\n\n`;
  }

  fs.writeFileSync(walletDetailsFilename, detailsContent);
  fs.writeFileSync(addressesFilename, allAddresses.join("\n") + "\n");

  console.log(`\nAll wallet details saved to: ${walletDetailsFilename}`);
  console.log(`Addresses only saved to: ${addressesFilename}`);

  rl.close();
}

async function deriveAddress(mnemonic: string, networkType: number, index: number) {
  if (!bip39.validateMnemonic(mnemonic)) {
    console.error("Invalid mnemonic phrase");
    return;
  }

  try {
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    const derived = deriveForNetwork(seed, networkType, 0, 0, 0, index);
    const pathString = derived.path
      .map((i: number) => (i & 0x7fffffff).toString() + (i & 0x80000000 ? "'" : ""))
      .join("/");
    console.log(`Derived Address: ${derived.address}`);
    console.log(`Path: ${pathString}`);
    console.log(`Network Type: ${derived.networkTypeName}`);
  } catch (error: any) {
    console.error("Derivation failed:", error.message);
  }
}

// Main CLI program
const program = new Command();

program
  .name("octra-wallet")
  .description("Octra Wallet Generator CLI")
  .version("1.0.0");

program
  .command("generate")
  .description("Generate a new wallet")
  .option("-s, --save", "Save wallet to file")
  .action(async (options) => {
    await generateWallet(options.save);
  });

program
  .command("generate-multi")
  .description("Generate multiple wallets and save them to files")
  .action(async () => {
    await generateMultipleWallets();
  });

program
  .command("derive")
  .description("Derive an address from mnemonic")
  .requiredOption("-m, --mnemonic <mnemonic>", "Mnemonic phrase")
  .option("-n, --network <type>", "Network type (0-4)", "0")
  .option("-i, --index <index>", "Derivation index", "0")
  .action(async (options) => {
    const networkType = parseInt(options.network);
    const index = parseInt(options.index);
    await deriveAddress(options.mnemonic, networkType, index);
  });

program.parse(process.argv);
