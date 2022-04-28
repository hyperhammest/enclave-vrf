//SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

// import "hardhat/console.sol";
import "./LibVRF.sol";

struct Proposal {
    address proposer;
    address[] newOperators;
    bytes newPubKey;
    uint votes; // bitmap
}

contract PubKeyGov {

    event NewOperatorsProposal(uint indexed id, address indexed proposer, address[] newOperators);
    event NewPubKeyProposal(uint indexed id, address indexed proposer, bytes newPubKey);
    event VoteProposal(uint indexed id, address indexed voter, bool agreed);
    event ExecProposal(uint indexed id);

    bytes public pubKey;
    address[] public operators;
    mapping(address => uint) private operatorSlots; // index+1 is stored actually
    uint public minProposalId;
    Proposal[] public proposals;

    modifier onlyOperator() {
        require(operatorSlots[msg.sender] > 0, 'not-operator');
        _;
    }

    constructor(address[] memory _operators, bytes memory _pubKey) {
        require(_operators.length > 0, 'no-operators');
        require(_operators.length <= 256, 'too-many-operators');
        require(_pubKey.length == 33, 'invalid-pubkey');
        pubKey = _pubKey;
        for (uint i = 0; i < _operators.length; i++) {
            setNewOperator(_operators[i], i);
        }
    }

    function getAllOperators() public view returns (address[] memory _operators) {
        _operators = operators;
    }
    function getProposal(uint id) public view returns (address proposer,
                                                       address[] memory newOperators,
                                                       bytes memory newPubKey,
                                                       uint votes) {
        Proposal storage proposal = proposals[id];
        proposer = proposal.proposer;
        newOperators = proposal.newOperators;
        newPubKey = proposal.newPubKey;
        votes = proposal.votes;
    }

    function proposeNewOperators(address[] memory newOperators) public onlyOperator {
        require(newOperators.length > 0, 'no-new-operators');
        require(newOperators.length <= 256, 'too-many-operators');
        proposals.push(Proposal(msg.sender, newOperators, '', 0));
        uint id = proposals.length - 1;
        _vote(id, true);
        emit NewOperatorsProposal(id, msg.sender, newOperators);
    }

    function proposeNewPubKey(bytes memory newPubKey) public onlyOperator {
        require(newPubKey.length == 33, 'invalid-pubkey');
        proposals.push(Proposal(msg.sender, new address[](0), newPubKey, 0));
        uint id = proposals.length - 1;
        _vote(id, true);
        emit NewPubKeyProposal(id, msg.sender, newPubKey);
    }

    function voteProposal(uint id, bool agreed) public onlyOperator {
        require(id >= minProposalId, 'outdated-proposal');
        require(id < proposals.length, 'no-such-proposal');
        _vote(id, agreed);
        emit VoteProposal(id, msg.sender, agreed);
    }
    function _vote(uint id, bool agreed) private {        
        uint idx = operatorSlots[msg.sender] - 1;
        uint mask = 1 << (idx & 0xff);
        if (agreed) {
            proposals[id].votes |= mask;
        } else {
            proposals[id].votes &= ~mask;
        }
    }

    function execProposal(uint id) public {
        require(id >= minProposalId, 'outdated-proposal');
        require(id < proposals.length, 'no-such-proposal');

        Proposal storage proposal = proposals[id];
        require(proposal.newPubKey.length > 0
            || proposal.newOperators.length > 0, 'executed-proposal');

        uint minVoteCount = operators.length * 2 / 3;
        uint voteCount = getVoteCount(proposal.votes);
        require(voteCount >= minVoteCount, 'not-enough-votes');

        if (proposal.newPubKey.length > 0) {
            pubKey = proposal.newPubKey;
            delete proposals[id];
        } else {
            clearOldOperators();
            setNewOperators(proposal.newOperators);
            minProposalId = proposals.length;
            delete proposals[id];
        }

        emit ExecProposal(id);
    }

    function getVoteCount(uint votes) private pure returns (uint n) {
        while (votes > 0) {
            n += votes & 1;
            votes >>= 1;
        }
    }
    function clearOldOperators() private {
        for (uint i = operators.length; i > 0; i--) {
            delete operatorSlots[operators[i - 1]];
            operators.pop();
        }
    }
    function setNewOperators(address[] storage newOperators) private {
        for (uint i = 0; i < newOperators.length; i++) {
            setNewOperator(newOperators[i], i);
        }
    }
    function setNewOperator(address operator, uint idx) private {
        require(operatorSlots[operator] == 0, 'duplicated-operators');
        operatorSlots[operator] = idx + 1;
        operators.push(operator);
    }


    function verify(uint blockHash, uint rdm, bytes calldata pi) public view returns (bool) {
        return LibVRF.verify(blockHash, pubKey, pi, rdm);
    }

}
