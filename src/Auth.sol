// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "openzeppelin-contracts/contracts/access/Ownable.sol";

/**
 * @title Auth
 * @dev The Auth contract manages authorization for specific function calls.
 */
contract Auth is Ownable {
    /**
     * @dev Emitted when an address is authorized to call a specific function.
     * @param authorizee The address that is authorized.
     * @param selector The function selector that is authorized.
     */
    event Authorize(address indexed authorizee, bytes4 indexed selector);
    /**
     * @dev Emitted when an address is deauthorized from calling a specific function.
     * @param authorizee The address that is deauthorized.
     * @param selector The function selector that is deauthorized.
     */
    event DeAuthorize(address indexed authorizee, bytes4 indexed selector);

    /**
     * @dev Error message for unauthorized function call.
     * @param caller The address of the caller.
     * @param selector The function selector of the unauthorized function call.
     */
    error Unauthorized(address caller, bytes4 selector);

    /**
     * @dev The mapping to store the authorization status of authorizees for specific function selectors.
     * authorizee => selector => authorized
     */
    mapping(address authorizee => mapping(bytes4 selector => bool auth)) public isAuthorized;

    /**
     * @dev Modifier to check if the caller is authorized for the function call.
     */
    modifier auth() {
        if (!isAuthorized[msg.sender][msg.sig]) revert Unauthorized(msg.sender, msg.sig);
        _;
    }

    /**
     * @dev Authorizes an address to call a specific function.
     * @param user The address to authorize.
     * @param signature The function signature to authorize.
     */
    function authorize(address user, bytes4 signature) public onlyOwner {
        isAuthorized[user][signature] = true;
        emit Authorize(user, signature);
    }

    /**
     * @dev Deauthorizes an address from calling a specific function.
     * @param user The address to deauthorize.
     * @param signature The function signature to deauthorize.
     */
    function deauthorize(address user, bytes4 signature) public onlyOwner {
        isAuthorized[user][signature] = false;
        emit DeAuthorize(user, signature);
    }
}
