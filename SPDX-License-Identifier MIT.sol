// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

library CryptoSuite{
    function splitSignature(bytes memory sig) internal pure returns(uint8 v,bytes32 r,bytes32 s){
        require(sig.length == 65);
 
       assembly {
                //first32bytes
                r:=mload(add(sig,32))

                //next32bytes
                s:=mload(add(sig,64))

                //last 32bytes
                v:=byte(0,mload(add(sig,96)))
        }
        return(v, r, s);
    }

    function recoverSigner(bytes32 message, bytes memory sig)internal pure returns(address){
        (uint8 v,bytes32 r,bytes32 s) = splitSignature(sig);
        
        return ecrecover(message, v, r, s);
    }
}

contract Organchain12 {
    enum Mode{ Issuer, Prover, Verifier }
    struct Entity{
        address id;
        Mode mode;
        uint[] certificateIds; 
    }

    enum Status{ ORGAN_RECOVERED, DELIVERING_LOCAL, DELIVERED }
    struct Certificate{
        uint id;
        Entity issuer;
        Entity prover;
        bytes signature;
        Status status;
    }

    struct Organ{
        uint id;
        string patient_name;
        address patient;
        uint[] certificateIds;
    }

    uint public constant MAX_CERTIFICATIONS = 2;

    uint[] public certificateIds;
    uint[] public organIds;

    mapping(uint => Organ) public organs;
    mapping(uint => Certificate) public certificates;
    mapping(address => Entity) public entities;

    event AddEntity(address entityId, string entityMode);    
    event AddOrgan(uint organId, address indexed donation);
    event IssueCertificate(address indexed issuer, address indexed prover, uint certificateId);

    function addEntity(address _id, string memory _mode) public {
        Mode mode = unmarshalMode(_mode);
        uint[] memory _certificateIds = new uint[](MAX_CERTIFICATIONS);
        Entity memory entity = Entity(_id, mode, _certificateIds);
        entities[_id] = entity;

        emit AddEntity(entity.id, _mode);
    }

    function unmarshalMode(string memory _mode) private pure returns(Mode mode){
        bytes32 encodedMode  = keccak256(abi.encodePacked(_mode));
        bytes32 encodedMode0 = keccak256(abi.encodePacked("ISSUER"));
        bytes32 encodedMode1 = keccak256(abi.encodePacked("PROVER"));
        bytes32 encodedMode2 = keccak256(abi.encodePacked("VERIFIER"));

        if(encodedMode == encodedMode0){
            return Mode.Issuer;
        }
        else if(encodedMode == encodedMode1){
            return Mode.Prover;
        }
        else if(encodedMode == encodedMode2){
            return Mode.Verifier;
        }
        revert("received invalid entity");
    }

    function addOrgan(string memory patient_name, address donation) public returns(uint){
        uint[] memory _certificateIds = new uint[](MAX_CERTIFICATIONS);
        uint id = organIds.length;
        Organ memory organ = Organ(id, patient_name, donation, _certificateIds);
        organs[id] = organ;

        emit AddOrgan(organ.id, donation);
        return id;
    }

function issueCertificate(
    address _issuer,
    address _prover,
    string memory _status,
    uint _organId,
    bytes memory _signature
) public returns (uint) {
    Entity memory issuer = entities[_issuer];
    require(issuer.mode == Mode.Issuer, "Invalid issuer mode");

    Entity memory prover = entities[_prover];
    require(prover.mode == Mode.Prover, "Invalid prover mode");

    Status status = unmarshalStatus(_status);

    require(organs[_organId].certificateIds.length < MAX_CERTIFICATIONS, "Maximum certifications reached");

    uint certificateId = certificateIds.length;
    certificateIds.push(certificateId);

    certificates[certificateId] = Certificate({
        id: certificateId,
        issuer: issuer,
        prover: prover,
        signature: _signature,
        status: status
    });

    organs[_organId].certificateIds.push(certificateId);

    emit IssueCertificate(_issuer, _prover, certificateId);

    return certificateId;
}


function isMatchingSignature(bytes32 message, uint id, address issuer) public view returns(bool){
    Certificate memory cert = certificates[id];
    require(cert.issuer.id == issuer);

    (uint8 v, bytes32 r, bytes32 s) = CryptoSuite.splitSignature(cert.signature);
    address recoverSigner = CryptoSuite.recoverSigner(message, cert.signature);

    return recoverSigner == cert.prover.id;
}

function unmarshalStatus(string memory _status) private pure returns(Status status){
    bytes32 encodedStatus  = keccak256(abi.encodePacked(_status));
    bytes32 encodedStatus0 = keccak256(abi.encodePacked("ORGAN_RECOVERED"));
    bytes32 encodedStatus1 = keccak256(abi.encodePacked("DELIVERING_LOCAL"));
    bytes32 encodedStatus2 = keccak256(abi.encodePacked("DELIVERED"));

    if(encodedStatus == encodedStatus0){
        return Status.ORGAN_RECOVERED;
    }
    else if(encodedStatus == encodedStatus1){
        return Status.DELIVERING_LOCAL;
    }
    else if(encodedStatus == encodedStatus2){
        return Status.DELIVERED;
    }
    revert("received invalid status");
}
uint public numCertificates;



}