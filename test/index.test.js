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
        proof: fromHex('0x1a8e210a475fc26601a3a42d3aee1b51c5feacb46157cf087eff760a0764687a304bd9c378103f302a270d8174661b2063396a196cd7d490324592910f73bb002f1da8eea493de2b6ebef085f6faacf95971ae7215be87fb663cb1591771e90d24a0adbb3e1de414327872b86d3a841f4a90fb0e0c607dbae653a99d6c00fefb1ecf81226147412c28b3800cbf91550ee9b88f59ccdb43d01527f7716850fc3b184aaa6e51ac883870ab4643b9e512890c19091485cc869b1086f9ec8c87fc802856f6d65e89949306f789769a45f751182dc9f77b19db59714d7e0a0eb6494d2df41c7deeefc4def5f9e13cbe658602776730549810a814f9c1a5368f0c89c023febd32fbd80e2d26e54f8d4737aa4d32b635fba615f57698177cf14cbad9111b85423af6d5979ccb5a32c8a636595a0c3f31742f78e408efb840a41ce72c1d2baa8d4512a4b31f8800a3511cf5892f440fc8bd836233fde8f47b2e61e283742add84013304f14e33e6e3c847b69be00e6dfcb8fa90e7e1595d9f8a12675f24166673764e1604d381d197457dd0026f5cf23084d9f9a46a181a06e369d801982e156ffb632be3f4c44ea07bef60bae2c210dea6847bb3d99498bdac17f5971b1d5d08f7a1bd3786fa015b3fd40137988aeda2c80315c5dc69c34e536b8eb21d0bf1e86ce71c668262a88e16d2ef40075732ad7593cad8a373a939b701b1793d0fff9022296b3d775e2b29a3af02aa0fb799f93e2ab87b73f3d7984b60f05bc81836186253e4b6bcaa4025b9222b8198692f10c78b7b9f51c295e922ee489ee017f7fec4426eeb72fbc5a99092d12fe1aa30ea5172be91b9775642e021a00cd11ef9013a5b599f053bed841c497c639aee2a55da2b034f7a503301811f1716bd261fd35ac0f09c9095b91ee0f5ca9d1ba259f679893f5c420bdc191623e8638605d748a60e3a3e8d7c271a13a9f32cc8767af73981f64ad020c88c0cc2a9fe4e1e94e215719940a0065afc7229f6380f236e0b1bf089225339ca99563da4ce642d7c30b994a48df2c32ef03da08f3c0688c25a76a0fbee9744e293cf0d570a19277ed8c4ba96ac500827cb55bbe654a734830e6fd4700c1fcf206bd63339726522a664f505dc90133c27413bbff1aaad7057a089039677ef540cbb92871608942344755c0c9a037c061fe00869dcfa54dd7e573f5e2d9b053398c09104f56d712dd2b9deb5635b034dea42eb5db74367afc8a20bcd80c6b628c03c61b801aa7f229fdf1efeb56b619e469b0ea7b7d6b7cb3aed5c6bb32e164351078d880b7eda125079ba5dc2d2b25068a1aa01a109294d952f6e3dd5792a01ddf4f9135112892f4528e5563aa6eabd18a1b6fcc4552df2b85b6b57e0f5c32cb7171570c59b1e2c8d9787e7134047790a9c897220be223864b105c508fc99bbd2f761af45957510492a198475381ab29e4421f16b879d75d0458e79d89ca873285b2ecf367e7b228470db3e1879fab0ecd6b021ae6b4fdafe9163d7d4b9278ed72069147e074504b92d40c87561ee0a0bf5a7af812bb1eaeed727f2c352ecc3638330b21b0f0d2bb47f023f9957e4eae3e33de440aed50b11aac85c2fe9455e2f63b5340bd9571baab0229fa5517a4244e69e80dc0eaeb3ad8e787deda36d95fadea94a8fae172d8667bbfbd4e47c780462fb8f5030484fdfdbd267d63b371d3e3313bb9f73f71d338e3deb37df672121759afc38ac6cbf8ddbcb75518c63cedeea6c2aacc5980336e8e412c4c2adaebb98e5ccafa49956944f1b761fd99fdf74727118ea40262005ab2a600e28f4efdb0f41ee9b7443c7ef09baa05cf019d856a83c7f934f4108d2fe4b39bd746f4eaae8d09b52a261bbc2b101c42be0fa83ab620cd504413f0a90218c201adaf5f0b9816194e245f9b06c04bfd77df6f563add4fc50a3c05416e85193d1e15d117bc70e789aecac66afe7ca3c4624c8efec9bdda10aeccb42256001e6d7a8b8fc5f3acfb35621dfe80b12aec863a2306930e885b37a39048b1de8792680505ce969ded4be51724a2852deb5348151a6935f56a6ec5649501323a5101ef0b8b290b627add1de76249de68efc836b48663b78ba3ad04e94119425d41c3a41a76395d625a87d332cdcdaad5e5ba25d24849ca1be8f6ca5aabebf14830b34a6862bdc3cfd6ed81c3c9ee1216155ef98edd8b0c89d44491cef95e205024f31b3bd6472f9a7995ff2d14c44ce64ae1fb2cf507e2dfc73bc65df262402db23d146aa0bfe6c7f477da128a2c94909fe56bf566765d43378c21552097a212a6207db1ae78ac34c86ff6493e11186c5e6edb0d39c5b85b61fc7d2896149138df0c44d43f31189ec9538f9267f0caa301694c3c32984fe1ac3ddfcbd4f0f14a229720f0608bb729bab8db4347b9f2b40cb0646a80c6c2a8e82c42a74a4370d7eeae63da84a89d6911eff099092a406c9b0279c8155f8a1d2694eadf598230d2b22bf9c651e48a24b6fc50a467fc3d8ea768cf1eecfd2c3c13b0f90ce31771b406c3a385542492bd691c6f5bcb7e774656ec1f92574d0b029e58b42d925691c8446d42b5e253ab2d7e500adc1b9cc07f4a58ae78d66b08d17be77643028b81f43740ae82d42fc074a306c13559d8ea0e024b5d18c99b540a3392c0c08c0721bf5f7f69d69f5f9f0e1cc224dc92c5f26bd81e25aed7394dff3b0e4f49fe5740f7870df2ad0afe3fbb133b9cd35dc7c37286bd1eb790d71d25e06e44566593e037876f600dfcbab8d2abd5128ec54b3cddc51a8faa8b8739953299db20e4d7013476aff766448de38b0a8132ecec3092eb98e6d9be8a2c67c4dd29733f6bd971f66802d14520eba097909ffb05f0858b8956b9106818948b348b39cb01872e12bdcb73d0166965b497c55e745a77f41688c72b51306c41f54febdbb6f3d58400bb8dc6727f2098fd9ee5a5a081e48c9f3172d3abc15a3767adabab7a94b8e5404ff6415d950d844b0ded590d285271f7a76cc316da6aaec6a4448a188d6e24a', 'bytes'),
        publicInputs: proof.publicInputs,
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
      console.log(proofData);
      const verifier = await ethers.deployContract('../artifacts/circuits/secp256k1/contract/secp256k1/plonk_vk.sol:UltraVerifier', [], {});
      const result = await verifier.verify(proofData.proof, proofData.publicInputs);

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
