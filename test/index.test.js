const hre = require('hardhat');
const { fromHex, hashMessage, recoverPublicKey, toHex } = require("viem")

const { BarretenbergBackend } = require ('@noir-lang/backend_barretenberg');
const { Noir }  = require ('@noir-lang/noir_js');

const circuit = require ("../circuits/target/stealthdrop.json");
const { expect } = require("chai")

describe('Setup', () => {
  let hashedMessage;
  let verifier;
  let noir;

  before(async () => {
    const messageToHash = '0xabfd76608112cc843dca3a31931f3974da5f9f5d32833e7817bc7e5c50c7821e';
    publicClient = await hre.viem.getPublicClient();
    verifier = await hre.viem.deployContract('UltraVerifier');
    hashedMessage = hashMessage(messageToHash, "hex");
  });

  describe('Airdrop tests', () => {

    before(async () => {
      const backend = new BarretenbergBackend(circuit, { threads: 8 });
      noir = new Noir(circuit, backend);
    });

    let proof;
    it("Generates a correct proof for an eligible user", async () => {
      const [user1] = await hre.viem.getWalletClients();
      const signature = await user1.signMessage({ account: user1.account.address, message: messageToHash })
      const pubKey = await recoverPublicKey({hash: hashedMessage, signature});
      const inputs = {
          pub_key: [...fromHex(pubKey, "bytes").slice(1)],
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
      await verifier.read.verify([toHex(proof.proof), proof.publicInputs.map(e => toHex(e))]);
    });
  });
});
