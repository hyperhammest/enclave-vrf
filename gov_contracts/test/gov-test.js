const { expect } = require("chai");
const { ethers } = require("hardhat");

const zeroAddr = '0x0000000000000000000000000000000000000000';
const testPubKey1 = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef33';
const testPubKey2 = '0x032bc8940f14a7822a58c4c2c22b15b83dcb157bff9e9cad16e88e3449a4fe4b63';

describe("PubKeyGov", function () {

  let op1, op2, op3, op4, op5, op6;
  let PubKeyGov;

  before(async () => {
    [op1, op2, op3, op4, op5, op6] = await ethers.getSigners();
    PubKeyGov = await ethers.getContractFactory("PubKeyGov");
  });

  it("init: errors", async () => {
    await expect(PubKeyGov.deploy([], testPubKey1))
      .to.be.revertedWith('no-operators');
    await expect(PubKeyGov.deploy(Array(257).fill(op1.address), testPubKey1))
      .to.be.revertedWith('too-many-operators');
    await expect(PubKeyGov.deploy([op1.address, op2.address, op1.address], testPubKey1))
      .to.be.revertedWith('duplicated-operators');
    await expect(PubKeyGov.deploy([op1.address, op2.address], '0x1234'))
      .to.be.revertedWith('invalid-pubkey');
  });

  it("init: ok", async () => {
    const ops = [op1.address, op2.address, op3.address];
    const gov = await PubKeyGov.deploy(ops, testPubKey1);
    await gov.deployed();
    expect(await gov.pubKey()).to.equal(testPubKey1);
    expect(await gov.getAllOperators()).to.deep.equal(ops);
  });

  it("propose: errors", async () => {
    const ops = [op1.address, op2.address, op3.address];
    const gov = await PubKeyGov.deploy(ops, testPubKey1);
    await gov.deployed();

    await expect(gov.connect(op5).proposeNewOperators([op5.address]))
      .to.be.revertedWith('not-operator');
    await expect(gov.proposeNewOperators([]))
      .to.be.revertedWith('no-new-operators');
    await expect(gov.proposeNewOperators(Array(258).fill(op1.address)))
      .to.be.revertedWith('too-many-operators');

    await expect(gov.connect(op5).proposeNewPubKey(testPubKey1))
      .to.be.revertedWith('not-operator');
    await expect(gov.proposeNewPubKey(testPubKey1 + 'ff'))
      .to.be.revertedWith('invalid-pubkey');
  });

  it("propose: ok", async () => {
    const ops = [op1, op2, op3, op4, op5, op6];
    const gov = await PubKeyGov.deploy(ops.map(x => x.address), testPubKey1);
    await gov.deployed();

    const newOps = [op4.address, op3.address, op2.address];
    for (let i = 0; i < 3; i++) {      
      await expect(gov.connect(ops[i * 2]).proposeNewPubKey(testPubKey2))
        .to.emit(gov, 'NewPubKeyProposal')
        .withArgs(i * 2, ops[i * 2].address, testPubKey2);
      await expect(gov.connect(ops[i * 2 + 1]).proposeNewOperators(newOps))
        .to.emit(gov, 'NewOperatorsProposal')
        .withArgs(i * 2 + 1, ops[i * 2 + 1].address, newOps);
    }

    // console.log(JSON.stringify(await gov.getProposal(0)))
    // expect(await gov.proposals(0)).to.equal({});
    expect(await getAllProposals(gov)).to.deep.equal([
      { id: 0, proposer: op1.address, newOps: [],     newPubKey: testPubKey2, votes:      '1' },
      { id: 1, proposer: op2.address, newOps: newOps, newPubKey: '0x',        votes:     '10' },
      { id: 2, proposer: op3.address, newOps: [],     newPubKey: testPubKey2, votes:    '100' },
      { id: 3, proposer: op4.address, newOps: newOps, newPubKey: '0x',        votes:   '1000' },
      { id: 4, proposer: op5.address, newOps: [],     newPubKey: testPubKey2, votes:  '10000' },
      { id: 5, proposer: op6.address, newOps: newOps, newPubKey: '0x',        votes: '100000' },
    ]);
  });

  it("vote: errors", async () => {
    const ops = [op1.address, op2.address, op3.address];
    const gov = await PubKeyGov.deploy(ops, testPubKey1);
    await gov.deployed();

    const newOps = [op4.address, op3.address, op2.address];
    await gov.connect(op2).proposeNewOperators(newOps);   // proposal#1
    await gov.connect(op3).proposeNewPubKey(testPubKey2); // proposal#2

    await expect(gov.connect(op4).voteProposal(0, true))
      .to.be.revertedWith('not-operator');
    await expect(gov.connect(op5).voteProposal(1, false))
      .to.be.revertedWith('not-operator');
    await expect(gov.connect(op1).voteProposal(2, false))
      .to.be.revertedWith('no-such-proposal');
  });

  it("vote: ok", async () => {
    const ops = [op1, op2, op3, op4, op5].map(x => x.address);
    const gov = await PubKeyGov.deploy(ops, testPubKey1);
    await gov.deployed();

    const newOps = [op4.address, op3.address, op2.address];
    await gov.connect(op2).proposeNewOperators(newOps);   // proposal#0
    await gov.connect(op3).proposeNewPubKey(testPubKey2); // proposal#1
    expect(await getAllProposals(gov)).to.deep.equal([
      { id: 0, proposer: op2.address, newOps: newOps, newPubKey: '0x',        votes:  '10' },
      { id: 1, proposer: op3.address, newOps: [],     newPubKey: testPubKey2, votes: '100' },
    ]);

    await expect(gov.connect(op1).voteProposal(1, true))
      .to.emit(gov, 'VoteProposal')
      .withArgs(1, op1.address, true);
    expect(await getAllProposals(gov)).to.deep.equal([
      { id: 0, proposer: op2.address, newOps: newOps, newPubKey: '0x',        votes:  '10' },
      { id: 1, proposer: op3.address, newOps: [],     newPubKey: testPubKey2, votes: '101' },
    ]);

    await expect(gov.connect(op2).voteProposal(0, false))
      .to.emit(gov, 'VoteProposal')
      .withArgs(0, op2.address, false);
    expect(await getAllProposals(gov)).to.deep.equal([
      { id: 0, proposer: op2.address, newOps: newOps, newPubKey: '0x',        votes:   '0' },
      { id: 1, proposer: op3.address, newOps: [],     newPubKey: testPubKey2, votes: '101' },
    ]);
  });

  it("exec: errors", async () => {
    const ops = [op1, op2, op3].map(x => x.address);
    const gov = await PubKeyGov.deploy(ops, testPubKey1);
    await gov.deployed();

    const newOps = [op2, op3, op4].map(x => x.address);
    await gov.connect(op2).proposeNewOperators(newOps);   // proposal#0
    await gov.connect(op2).proposeNewPubKey(testPubKey2); // proposal#1
  
    await expect(gov.connect(op1).execProposal(2))
      .to.be.revertedWith('no-such-proposal');
    await expect(gov.connect(op1).execProposal(1))
      .to.be.revertedWith('not-enough-votes');

    await gov.connect(op3).voteProposal(1, true);
    await gov.connect(op4).execProposal(1);
    await expect(gov.connect(op1).execProposal(1))
      .to.be.revertedWith('executed-proposal');

    await gov.connect(op3).voteProposal(0, true);
    await gov.connect(op4).execProposal(0);
    await expect(gov.connect(op1).execProposal(0))
      .to.be.revertedWith('outdated-proposal');
    await expect(gov.connect(op1).execProposal(1))
      .to.be.revertedWith('outdated-proposal');
  });

  it("exec: ok", async () => {
    const ops = [op1, op2, op3].map(x => x.address);
    const gov = await PubKeyGov.deploy(ops, testPubKey1);
    await gov.deployed();

    const newOps = [op2, op3, op4].map(x => x.address);
    await gov.connect(op2).proposeNewOperators(newOps);   // proposal#0
    await gov.connect(op2).proposeNewPubKey(testPubKey2); // proposal#1
    expect(await getAllProposals(gov)).to.deep.equal([
      { id: 0, proposer: op2.address, newOps: newOps, newPubKey: '0x',        votes: '10' },
      { id: 1, proposer: op2.address, newOps: [],     newPubKey: testPubKey2, votes: '10' },
    ]);

    await gov.connect(op3).voteProposal(1, true);
    await expect(gov.connect(op4).execProposal(1))
      .to.emit(gov, 'ExecProposal').withArgs(1);
    expect(await gov.pubKey()).to.equal(testPubKey2);

    await gov.connect(op3).voteProposal(0, true);
    await expect(gov.connect(op4).execProposal(0))
      .to.emit(gov, 'ExecProposal').withArgs(0);
    expect(await gov.getAllOperators()).to.deep.equal(newOps);

    // proposal data is cleared
    expect(await getAllProposals(gov)).to.deep.equal([
      { id: 0, proposer: zeroAddr, newOps: [], newPubKey: '0x', votes: '0' },
      { id: 1, proposer: zeroAddr, newOps: [], newPubKey: '0x', votes: '0' },
    ]);
  });

  it("verify: ok", async () => {
    const ops = [op1, op2, op3].map(x => x.address);
    const gov = await PubKeyGov.deploy(ops, testPubKey2);
    await gov.deployed();

    // await gov.verify(
    //   '0x6f6a4acddaf0a10fdb5418503f0cd061051cc9385d9591e439874e12b4da6975',
    //   '0xf1f42162b587551c0f9d1eb08bb059b159274af3473b47411575bb3783c9b555',
    //   '0x024901ff0ac6779c4194a44f32fd9417f487b9a7432c9e7e8b875c176a606ee2cf81dd738c4f86f176c8bbe77b925e8a480a60cfaf262bfc8fae7fc45257773112fde746f3829a809e2ff27c0c13126e15',
    // );
  });

});

async function getAllProposals(gov) {
  const proposals = [];
  for (let i = 0; ; i++) {
    try {
      proposals.push(await getProposal(gov, i));
    } catch (err) {
      // console.log(err);
      break;
    }
  }
  return proposals;
}
async function getProposal(gov, id) {
  let [proposer, newOps, newPubKey, votes] = await gov.getProposal(id);
  votes = BigInt(votes.toString()).toString(2);
  return {id, proposer, newOps, newPubKey, votes};
}
