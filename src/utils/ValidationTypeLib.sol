// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IValidator, IPolicy} from "../interfaces/IERC7579Modules.sol";
import {PassFlag, ValidationType, ValidationId, ValidationMode, PolicyData, PermissionId} from "../types/Types.sol";
import {VALIDATION_TYPE_PERMISSION} from "../types/Constants.sol";

library ValidatorLib {
    function encodeFlag(bool skipUserOp, bool skipSignature) internal pure returns (PassFlag flag) {
        assembly {
            if skipUserOp { flag := 0x0001000000000000000000000000000000000000000000000000000000000000 }
            if skipSignature { flag := or(flag, 0x0002000000000000000000000000000000000000000000000000000000000000) }
        }
    }

    function encodePolicyData(bool skipUserOp, bool skipSig, address policy) internal pure returns (PolicyData data) {
        assembly {
            if skipUserOp { data := 0x0001000000000000000000000000000000000000000000000000000000000000 }
            if skipSig { data := or(data, 0x0002000000000000000000000000000000000000000000000000000000000000) }
            data := or(data, shl(80, policy))
        }
    }

    function encodePermissionAsNonce(bytes1 mode, bytes4 permissionId, uint16 nonceKey, uint64 nonce)
        internal
        pure
        returns (uint256 res)
    {
        return encodeAsNonce(
            mode, ValidationType.unwrap(VALIDATION_TYPE_PERMISSION), bytes20(permissionId), nonceKey, nonce
        );
    }

    function encodeAsNonce(bytes1 mode, bytes1 vType, bytes20 ValidationIdWithoutType, uint16 nonceKey, uint64 nonce)
        internal
        pure
        returns (uint256 res)
    {
        assembly {
            res := nonce
            res := or(res, shl(64, nonceKey))
            res := or(res, shr(16, ValidationIdWithoutType))
            res := or(res, shr(8, vType))
            res := or(res, mode)
        }
    }

    function encodeAsNonceKey(bytes1 mode, bytes1 vType, bytes20 ValidationIdWithoutType, uint16 nonceKey)
        internal
        pure
        returns (uint192 res)
    {
        assembly {
            res := or(nonceKey, shr(80, ValidationIdWithoutType))
            res := or(res, shr(72, vType))
            res := or(res, shr(64, mode))
        }
    }

    function decodeNonce(uint256 nonce)
        internal
        pure
        returns (ValidationMode mode, ValidationType vType, ValidationId identifier)
    {
        // 2bytes mode (1byte currentMode, 1byte type)
        // 21bytes identifier
        // 1byte mode  | 1byte type | 20bytes identifierWithoutType | 2byte nonceKey | 8byte nonce == 32bytes
        assembly {
            mode := nonce
            vType := shl(8, nonce)
            identifier := shl(8, nonce)
            switch shr(248, identifier)
            case 0x0000000000000000000000000000000000000000000000000000000000000002 {
                identifier := and(identifier, 0xffffffffff000000000000000000000000000000000000000000000000000000)
            }
        }
    }

    function decodeSignature(bytes calldata signature) internal pure returns (ValidationId vId, bytes calldata sig) {
        assembly {
            vId := calldataload(signature.offset)
            switch shr(248, vId)
            case 0 {
                // sudo mode
                vId := 0x00
                sig.offset := add(signature.offset, 1)
                sig.length := sub(signature.length, 1)
            }
            case 1 {
                // validator mode
                sig.offset := add(signature.offset, 21)
                sig.length := sub(signature.length, 21)
            }
            case 2 {
                vId := and(vId, 0xffffffffff000000000000000000000000000000000000000000000000000000)
                sig.offset := add(signature.offset, 5)
                sig.length := sub(signature.length, 5)
            }
            default { revert(0x00, 0x00) }
        }
    }

    function decodePolicyData(PolicyData data) internal pure returns (PassFlag flag, IPolicy policy) {
        // PolicyData is bytes32

        // 80 bits is 10 bytes, which leaves 22 bytes for the policy.
        assembly {
            flag := data
            policy := shr(80, data)
        }
    }

    function validatorToIdentifier(IValidator validator) internal pure returns (ValidationId vId) {
        // NOTE: 1. start out with 256 bits of 0 (with the 1 at the beginning)

        // NOTE: 2. the address is 160 bits: shift it 88 bits to the left, which gets us 248.
        // NOTE:    256 - 248 = 8 bits left over. There are 4 bits per hex value, and there are 2 hex values taken up.
        // NOTE:    given that 01 are the first two hex values, we're looking at:
        //          0x01<address> (22 hex values is 88 bits)

        // EXAMPLE: if address is: 0xA463C7164A7A78320e974651472707b4E85d592D,

        // 1. assign 0x01.... (256 bits)
        // 2. shift the address 88 bits to the left:
        //    00A463C7164A7A78320e974651472707b4E85d592D0000000000000000000000
        // 3. merge the two togher
        // vId = 0x01A463C7164A7A78320e974651472707b4E85d592D0000000000000000000000 (64 bytes)

        // 4. type cast into ValidationId, which is 21 bytes (42 hex values) -- we subtract the 22 zeros at the end
        //    0x01A463C7164A7A78320e974651472707b4E85d592D

        assembly {
            vId := 0x0100000000000000000000000000000000000000000000000000000000000000
            vId := or(vId, shl(88, validator))
        }
    }

    function getType(ValidationId validator) internal pure returns (ValidationType vType) {
        // EXAMPLE: if address is: 0xA463C7164A7A78320e974651472707b4E85d592D,
        // validator = 0x01A463C7164A7A78320e974651472707b4E85d592D0000000000000000000000

        // NOTE: this is extracting the first bytes1 value, 01 (assumes big endian)
        assembly {
            vType := validator
        }
    }

    function getValidator(ValidationId validator) internal pure returns (IValidator v) {
        assembly {
            v := shr(88, validator)
        }
    }

    // THE PERMISSION ID IS THE FIRST 4 BYTES OF THE ADDRESS (FIRST 8 HEX VALUES)
    function getPermissionId(ValidationId validator) internal pure returns (PermissionId id) {
        // PermissionId is 4 bytes, so that's 8 hex values

        // input: 0x02A463C7164A7A78320e974651472707b4E85d592D0000000000000000000000
        // shift left: give example
        // output: bytes4: id 0xa463c716

        assembly {
            id := shl(8, validator)
        }
    }

    function permissionToIdentifier(PermissionId permissionId) internal pure returns (ValidationId vId) {
        // EXAMPLE: if address is: 0xA463C7164A7A78320e974651472707b4E85d592D,
        // validator = 0x02A463C7164A7A78320e974651472707b4E85d592D0000000000000000000000

        assembly {
            vId := 0x0200000000000000000000000000000000000000000000000000000000000000
            vId := or(vId, shr(8, permissionId))
        }
    }

    function getPolicy(PolicyData data) internal pure returns (IPolicy vId) {
        assembly {
            vId := shr(80, data)
        }
    }

    function getPermissionSkip(PolicyData data) internal pure returns (PassFlag flag) {
        assembly {
            flag := data
        }
    }
}
