const hre = require('hardhat');
const { fromHex, hashMessage, recoverPublicKey, toHex, compactSignatureToSignature } = require("viem")
const { ethers } =require('hardhat');

const { BarretenbergBackend } = require ('@noir-lang/backend_barretenberg');
const { Noir }  = require ('@noir-lang/noir_js');

const c_secp256k1 = require ("../circuits/secp256k1/target/secp256k1.json");
const c_secp256r1 = require ("../circuits/secp256r1/target/secp256r1.json");
const secp256r1 = require('secp256r1')
const { expect } = require("chai")

describe('Setup', () => {
  const messageToHash = '0xabfd76608112cc843dca3a31931f3974da5f9f5d32833e7817bc7e5c50c7821e';
  let hashedMessage;

  describe('secp256k1 tests', () => {
  let noir;
    before(async () => {
      publicClient = await hre.viem.getPublicClient();
      
      hashedMessage = hashMessage(messageToHash, "hex");

      const backend = new BarretenbergBackend(c_secp256k1, { threads: 8 });
      noir = new Noir(c_secp256k1, backend);
    });

    let proof;
    it("Generates a correct proof for an eligible user", async () => {
      const [user1] = await hre.viem.getWalletClients();
      const signature = await user1.signMessage({ account: user1.account.address, message: messageToHash })
      const pubKey = await recoverPublicKey({hash: hashedMessage, signature});
      const inputs = {
          pub_key_x: [...fromHex(pubKey, "bytes").slice(1).slice(0, 32)],
          pub_key_y: [...fromHex(pubKey, "bytes").slice(33)],
          signature: [...fromHex(signature, "bytes").slice(0, 64)],
          hashed_message: [...fromHex(hashedMessage, "bytes")],
      };

      proof = await noir.generateFinalProof(inputs)
    })

    it('Verifies correct proof off-chain', async () => {
      const verification = await noir.verifyFinalProof(proof);
      expect(verification).to.be.true;
    });

    it('Verifies correct proof on-chain', async () => {
      // Print proof to ease debugging
      console.log(proof);
      
      // viem
      // const verifier = await hre.viem.deployContract('../artifacts/circuits/secp256k1/contract/secp256k1/plonk_vk.sol:UltraVerifier');
      // const result = await verifier.read.verify([toHex(proof.proof), proof.publicInputs.map(e => toHex(e))]);
      
      // ethers
      const verifier = await ethers.deployContract('../artifacts/circuits/secp256k1/contract/secp256k1/plonk_vk.sol:UltraVerifier', [], {});
      const result = await verifier.verify(proof.proof, proof.publicInputs);

      expect(result).to.be.true;
    });
  });

  // Commenting secp256r1 out to focus on secp256k1 first.
  /**
  describe.only('secp256r1 tests', () => {
  let noir;

    before(async () => {
      publicClient = await hre.viem.getPublicClient();
      const verifier = await hre.viem.deployContract('../artifacts/circuits/secp256r1/contract/secp256r1/plonk_vk.sol:UltraVerifier');
      hashedMessage = hashMessage(messageToHash, "hex");

      const backend = new BarretenbergBackend(c_secp256r1, { threads: 8 });
      noir = new Noir(c_secp256r1, backend);
    });

    let proof;
    it("Generates a correct proof for an eligible user", async () => {
      const privKey = Buffer.from("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", "hex")
      const pubKey = secp256r1.publicKeyCreate(privKey)
      const uncompressedPubKey = secp256r1.publicKeyConvert(pubKey, false)
      const msg = Buffer.from(fromHex(messageToHash, "bytes"))
      const signature = secp256r1.sign(msg, privKey)
      console.log("local secp256r1 verification", secp256r1.verify(msg, signature.signature, pubKey))

      const inputs = {
          pub_key_x: [...uncompressedPubKey.slice(1).slice(0, 32)],
          pub_key_y: [...uncompressedPubKey.slice(33)],
          signature: [...signature.signature],
          hashed_message: [...msg],
      };

      console.log(inputs)

      proof = await noir.generateFinalProof(inputs)
      console.log(proof)
    })

    it('Verifies correct proof off-chain', async () => {
      const verification = await noir.verifyFinalProof(proof);
      expect(verification).to.be.true;
    });

    it('Verifies correct proof on-chain', async () => {
      await verifier.read.verify([toHex(proof.proof), proof.publicInputs.map(e => toHex(e))]);
    });
  });
  */
});
