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
     * @param user The address that is authorized.
     * @param selector The function selector that is authorized.
     */
    event Authorize(address indexed user, bytes4 indexed selector);
    /**
     * @dev Emitted when an address is deauthorized from calling a specific function.
     * @param user The address that is deauthorized.
     * @param selector The function selector that is deauthorized.
     */
    event DeAuthorize(address indexed user, bytes4 indexed selector);

    /**
     * @dev Error message for unauthorized function call.
     * @param caller The address of the caller.
     * @param selector The function selector of the unauthorized function call.
     */
    error Unauthorized(address caller, bytes4 selector);

    /**
     * @dev The mapping to store the authorization status of authorizees for specific function selectors.
     */
    mapping(address caller => mapping(bytes4 selector => bool auth)) private isAuthorized;

    /**
     * @dev Modifier to check if the caller is authorized for the function call.
     */
    modifier auth() {
        if (!isAuthorized[msg.sender][msg.sig]) revert Unauthorized(msg.sender, msg.sig);
        _;
    }

    /**
     * @dev Gets the authorization state of an address to call a specific function.
     * @param user The address to authorize.
     * @param selector The function selector to authorize.
     */
    function getAuthoziation(address user, bytes4 selector) external view returns (bool) {
        return isAuthorized[user][selector];
    }
    /**
     * @dev Authorizes an address to call a specific function.
     * @param user The address to authorize.
     * @param selector The function selector to authorize.
     */

    function _authorize(address user, bytes4 selector) internal onlyOwner {
        isAuthorized[user][selector] = true;
        emit Authorize(user, selector);
    }

    /**
     * @dev Deauthorizes an address from calling a specific function.
     * @param user The address to deauthorize.
     * @param selector The function selector to deauthorize.
     */
    function _deauthorize(address user, bytes4 selector) internal onlyOwner {
        isAuthorized[user][selector] = false;
        emit DeAuthorize(user, selector);
    }
}
