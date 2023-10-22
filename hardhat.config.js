require ('@nomicfoundation/hardhat-toolbox-viem');
require ('@nomicfoundation/hardhat-chai-matchers');
require ('@nomicfoundation/hardhat-viem');

const config = {
  solidity: {
    version: '0.8.18',
    settings: {
      optimizer: { enabled: true, runs: 5000 },
    },
  },
  networks: {
    localhost: {
      url: 'http://127.0.0.1:8545',
    },
  },
  paths: {
    sources: './circuits/contract',
  },
  mocha: {
    timeout: 4000000
  }
};

module.exports = config;
