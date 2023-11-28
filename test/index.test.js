const hre = require('hardhat');
const { fromHex, hashMessage, recoverPublicKey, toHex, compactSignatureToSignature } = require("viem")
const { ethers } =require('hardhat');

const { BarretenbergBackend, flattenPublicInputs } = require ('@noir-lang/backend_barretenberg');
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

    let proofData;
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

      proofData = await noir.generateFinalProof(inputs)
    })

    it('Verifies correct proof off-chain', async () => {
      const verification = await noir.verifyFinalProof(proofData);
      expect(verification).to.be.true;
    });

    it('Verifies correct Nargo proof off-chain', async () => {
      const nargoProofData = {
        proof: fromHex('0x114b25e4844e93165e07651153b0c1794c9503c0717baabfe95e895681de901d2869452d0fd4b3274dfa2717ed2abffd12851db7907941910f7626b9ad2bd1f5249a75228282fae543fecf5a4de9b56349429a198da6c183c294da98b3ab45582d4ec33b5b96ae29aa7743da4cdd39893e553394094f9330e48c504ef17687890015e8d75e5ebb59ac9d45dbf286d865d08453f2d2fc6232bf32f458d41ddec11429cd7496a7893d1e8be70ee0f00aac39b4179811e21ce2cc3cfd051a2485b12ec38f3f055cf5e75c274ffd1d83e308463149e4cb941eed2b90de672caf1bdb00a3b4bdfdf3074af76dd992ebfceb19bb6bc3030e0d5ed9c660858c19de6c562c2262a9a73f205030db2f42b32578eab9b28fe5c749b7dbbc038dbf144246632c39e17b95c7748218e726f4313934d123973ed42938ac7c88251e772259cdc819e8086bcb83cf9a104262e884bf40057bc99734b745262b5315b7192e25a0780685fd2c15983c6d621cd44e72372d2bea44af10236eab65786b7a874db73e7f0ae4a8b005b891a5d02f2472911b614de4ea6b17a0ee038e18223ac8ebe875f60675b1fc8f3a227e4ec47fc77b6be7c217559880ad08bf250f1ebf462516f0841dd5cc1aa6c518b8691aa9e99fdb91aa561a4d7ccb205f5a6dc21cc2f82d7359172f022b493a16bb2a1b66b4b1b840ecaae752bac3fef7f8b6a897f8bff1aed2086ffafa9ca87f8b647457d2dd0715a0c11f68c75362698af734447a24eb546c0fa42bf575b3605d962cff58960d111ec69ffd8916998e62412ac6ab9c5b2edb118221f8b8bde564878498d0138b939b9ceb1a83bd8df2c07a7ae4e5c6adf6c01b7e4bd2f6ec387c383156f04084a5f29d1c03220d30e5ea7852361750a9fd7607621688e90c14a1b1402757ab31669e645f0033809257906e8e9f251f944c4725bab6ae315888ca17ea4265321f6d53995826b8303909ab463c29e00c522608205915c285c7fd08d819067ce2b078c424e6254870bd3210efa403f2ba2c01cb1e6657ab01e75d146342c2bd168f9b7f3427d0dabcc32c5f66b8e2ad78a0588103784e16da7e5a5b4d9617471fdecb664b7702bca0c8263887cc3a8ed25dd9dc11c174258478f7e6108ef7fd842d22445545dc083922c03a8b4fd5d235310dbb14a29595f0d32b946636070416f67d948c6bf1936a7ff042478b0c249da9c6f306740d6d12166cd7d9a7afd1115458fb55f2bd0b0b598c042ca8ab8bf01e079a29281e450a22f565ffd8e4193779d3f41d051dc314d52541b855a0181aa4529b2f2d00bb61d1c75c831cce5b9bd2c5be20ea04ee3b1369d0159c73e4c4a39c791763268755e7bb8bb363d9ef411baec427bdb4e67bba5947dc4f2baf94e073a71f49bd20e990541e821848995fe147136a5d8e2a6549903a00df68425eabf9d025f73ed726f55cedcbc9f899cabbc4356d5438a268796e1d4a07ad23c3828db027b263a1d1e5f4e130a5653e31ab1562334f22d71bd3a7c6eadd939dcf07bb1313ebde46088fbaf8bc88ce40553c179d9332660c57b613721f5002f5cb5862410a5b08da2b0e35425dffc19d2aed0b534e8d6717a9019032eada38d08ef7579b2cc1e84bf82236fccb7fc866c1d19d2908f3a5203d432ad3d99ced52dc9769fb14e537b0f75ff14414d1777c5355b8c95eca0040f230f1ee783a51cb4ee2a450025d35d26c49d9021cb0573323267ae2dcf28773c9f72954da955cbdf4ea0e5513e3978d33c9e58a7d7c0866205f9b45fbf60daaa171db2a6d3c7887f6fbec440bb3cb63e6a0b9a82be46b0e8e09752090cb84c834a6eaaa42c5526d76352a4f28621ade7776b306cd7521ffa273cc072985a4e32d00d17817cd4e8a324348582e6a12b7f21e4f5c9712ffb7e719c23b00e79f95622b4710e90f5afdc52c39ec0c95247d293372d42491ad195116227fa401c399e28c86c2317219e5f95ab82714819e8859a23e6c1e8e896c3dbee30726f161bdd96e5ff0d919ddae0770b3fb2f9d6d7f06534b11614c2da9d20310051f2be5e6a56bcc8d6b290e1d2f0e21370b1f4913f11f5382ca8824f497c72be59e0ec2e84e0af0f1d5125601e77c5a8f202dfec5045b179cd5ac4144d665ffadb0b25c299e98fdf40033dc1f0ea3ce15175a02f0c5cadd1d634f946614ade3ebabae1dc7b5d77248e410e68d8a92d9f20d183177808b5cb06ff61a107295dd045647cf5d5c69d23243fbf852c03b89fc19caae8f3789483bc07d2989a015e88e6108f72d7dc856a5c2dba05c7cba899012804535b0a62a725869ac205fbbdbf9af6938e7d5d85cc218dbbec1f3104346248c7d1a9dc7de47a14a092bafafbfdbfbd1d7ef05c77ad6f420b2476a5338de183dbe9c460289bc74ad403249842074675c35224eb12862a62d8a8f1b64579d22e25aaca45f098097ad39e3ca9e850fce344f6388256ad33426f88ebcb94f6d17dd5543722ecdb75d9b4801e450a13c0ed5dbc809bea979ab46ac16c9789e8b07128ffe638ac14030bca0d999cfb9e2b2bdb2bd744c021bcf6021fdb633534c112138b858c32321a7d80aaac86529ae21067aafb03f0f80426200d87f1656172341bcd28bb9364a2cd87b3951e9b4b5790cfdbad925253ae7752abb55d595390b3345b986d4561252d426af4649ff5fa529d2ec14d80250bbfbed88ef8c88c62ff0ab3f665385fb42f184f33d5ec0ad7de5d3eadc5c552003c384f339d9e7fa08890686e818e1e9453380829caf97dfb3b8afdf09f665547db20b65e3554a4402e79e6856b1014e8bfcf973751535d0e59044061cafca8155524d3eb43065a609843348a06f7180f026c4c0328af9b80f8f6c6a611ebed5337cbf76398f1f5f006d6dfe91f2aad83cb79e58feb42ef93c5d5a3c1ed2471e1d967878ba3817da11009d4628b46258813d97e24a7b787d0257b8bd4c011f46d80aee9739e17c8d0ef5d2658e71d7e2358752996e0eea5b26825e3f0a038b1ac8cf7b546848536f', 'bytes'),
        publicInputs: proofData.publicInputs,
      }
      const verification = await noir.verifyFinalProof(nargoProofData);
      expect(verification).to.be.true;
    });

    it('Verifies correct proof on-chain', async () => {
      // viem
      // const proof = toHex(proofData.proof);
      // const publicInputs = proofData.publicInputs.map(e => toHex(e));
      // console.log(proof); // For debugging
      // console.log (publicInputs); // For debugging
      // const verifier = await hre.viem.deployContract('../artifacts/circuits/secp256k1/contract/secp256k1/plonk_vk.sol:UltraVerifier');
      // const result = await verifier.read.verify([proof, publicInputs]);
      
      // ethers
      const verifier = await ethers.deployContract('../artifacts/circuits/secp256k1/contract/secp256k1/plonk_vk.sol:UltraVerifier', [], {});
      const result = await verifier.verify(proofData.proof, flattenPublicInputs(proofData.publicInputs));

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

    let proofData;
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

      proofData = await noir.generateFinalProof(inputs)
      console.log(proofData)
    })

    it('Verifies correct proof off-chain', async () => {
      const verification = await noir.verifyFinalProof(proofData);
      expect(verification).to.be.true;
    });

    it('Verifies correct proof on-chain', async () => {
      await verifier.read.verify([toHex(proofData.proof), proofData.publicInputs.map(e => toHex(e))]);
    });
  });
  */
});
