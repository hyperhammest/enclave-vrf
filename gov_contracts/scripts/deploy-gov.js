// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");

async function main() {
  // Hardhat always runs the compile task when running scripts with its command
  // line interface.
  //
  // If this script is run directly using `node` you may want to call compile
  // manually to make sure everything is compiled
  // await hre.run('compile');

  // We get the contract to deploy
  const PubKeyGov = await hre.ethers.getContractFactory("PubKeyGov");

  const signers = await ethers.getSigners();
  const ops = [
    '0x60d8666337C854686F2CF8A49B777c223b72fe34',
    '0xc370743331B37d3C6D0Ee798B3918f6561Af2C92',
    '0x394366844E04ad106CbDA583e98caf41f10Edd32',
  ];
  const pubKey = '0x032bc8940f14a7822a58c4c2c22b15b83dcb157bff9e9cad16e88e3449a4fe4b63';
  const gov = await PubKeyGov.deploy(ops, pubKey);
  await gov.deployed();
  console.log("PubKeyGov deployed to:", gov.address);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
