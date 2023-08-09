// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

//This link can be used for all the comments on the vulnarablities
//https://docs.google.com/document/d/1jjul8J1rrggd0HSKxS9om12nwW2GgJmykERcEzS-vuw/edit?usp=sharing

/*
Hi dear candidate!
Please review the following contract to find the 2 vulnerbilities that results 
in loss of funds.(High/Critical Severity)
Please write a short description for each vulnerbillity you found alongside with
a PoC in hardhat/foundry.
Your PoC submission should be ready to be run without any modification 
Feel free to add additional notes regarding informational/low severity findings
*/

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract PonziContract is ReentrancyGuard, Ownable {
    /*
    First of all, now we can use `error`s to decrease the cost of the contract by 
    not using strings in `require` statements. 
    Eg. 
    error NotAnAffiliate()
    */

    event RegistrationDeadline(uint256 registrationDeadline);
    event Withdraw(uint256 amount);

    uint256 private registrationDeadline;
    address[] public affiliates_;

    mapping(address => bool) public affiliates;
    uint256 public affiliatesCount;

    /*
    We have a couple of issues with the `onlyAfilliates` modifier above. 
    If say everything is OK, there is no need to compare `affiliate == true` 
    since affiliate itself is already boolean, either true or false. 
    So it  costs additional gas without any need.

    The modifier totally has been implemented in an inefficient way. 
    1. No need to variable `bool affiliate`
    2. No need to loop which is gonna cost lots of gas, 
        and considering that the `affiliates_` array is stored in ‘storage', 
        reading from storage is quite expensive. (say if we still need to 
        read from it, we could first save it into a new variable in `memory`, 
        then could loop over it. It would be quite efficient (hundreds times)
    3. Since we have a map in which we save each affiliate and define their 
        status as true, we can simply use it: 
        require(affiliates[msg.sender], “Not an Affiliate”);
    
    This is all we need here. So we would decrease the gas consumption fairly much. 
    And considering that this is a modifier that is gonna be used quite often. 
    */

    modifier onlyAfilliates() {
        bool affiliate;

        for (uint256 i = 0; i < affiliatesCount; i++) {
            if (affiliates_[i] == msg.sender) {
                affiliate = true;
            }
        }
        require(affiliate == true, "Not an Affiliate!");
        _;
    }

    /*
    Here in setDeadline function we have an issue:
    We need to check the _regDeadline to be not in past, otherwise 
    it is useless to set it ( if we do not use to stop the contract by setting it in this way)
    */

    function setDeadline(uint256 _regDeadline) external onlyOwner {
        registrationDeadline = _regDeadline;
        emit RegistrationDeadline(registrationDeadline);
    }

    /*
    Vulnarablity #1
    Here in `joinPonzi` function we have really serious issues:
    We do expect the caller to this function to add an array of addresses of affiliates, 
    but we do not have any checks against malicious addresses. So that way I can simply 
    add all just my address as many times as affiliatesCount, then all the ether will be 
    just sent back to my account and my address will be added to the affiliates array and 
    also affiliates map. I can do this as many times as I want ( if I have enough ether , 
    also for gas fees, since in every trnx I pay gas fee too). 
    Then say there are 10 affiliate addresses, 5 is just my address. 
    Now if someone new wants to join (they are innocent 😂) they pay 5 ether to me. 

    Also as I said here in this case someone can add themselves as many times as they want 
    into the ponzi. That is logically OK. But if we do not want it to happen, we can check 
    if they are in the ponzi already by simply 
    `require(!affiliates[msg.sender], “Already Affiliate”)`

    AND REALLY IMPORTANT is that we need to check the return value of the `call` function, 
    because it can be unsuccessful and this way we still proceed. 
    Modified: 
        `(bool success, ) = _afilliates[i].call{value: 1 ether}("");` 
        require(success, “Transaction failed”);
    Before using the `_affiliates` array in the loop we need to assign it into a new variable 
    in memory, so it would cost fairly less.

    How can we fix it?
    First of all we do not need the user to send ass affiliate addresses, we already have them. 
    We can assign the array into a new variable and loop over it. 
    */

    function joinPonzi(
        address[] calldata _afilliates
    ) external payable nonReentrant {
        require(
            block.timestamp < registrationDeadline,
            "Registration not Active!"
        );
        require(_afilliates.length == affiliatesCount, "Invalid length");
        require(msg.value == affiliatesCount * 1 ether, "Insufficient Ether");
        for (uint256 i = 0; i < _afilliates.length; i++) {
            _afilliates[i].call{value: 1 ether}("");
            //Here we definitely need to check the return value of `call`.
        }
        affiliatesCount += 1;
        affiliates[msg.sender] = true;
        affiliates_.push(msg.sender);
    }

    /*
    Vulnarablity #2
    I am not sure if this logic is specifically chosen. If so you can not continue to read 
    this comment. But the function below is a serious vulnerability to the contract. Say if 
    I want to buy ownership, I send 10 ethers and then I send them back to myself by using 
    `ownerWithdraw`. But also I can add new affiliates below in the `addNewAffilliate` function. 
    Say I can add hundreds of my address into the array and then whoever even buys the ownership 
    others would need to pay me to join to ponzi (using `joinPonzi`)

    There may be implemented various logics here, such as they may pay 10 ethers to every affiliate 
    in the ponzi. 
    */
    function buyOwnerRole(address newAdmin) external payable onlyAfilliates {
        require(msg.value == 10 ether, "Invalid Ether amount");
        _transferOwnership(newAdmin);
    }

    function ownerWithdraw(address to, uint256 amount) external onlyOwner {
        payable(to).call{value: amount}("");
        emit Withdraw(amount);
    }

    /*
    Here we can check also it the affiliate is already added or not. And if we need each affiliate 
    to be added once only, then we need to 
    `require(!affiliates[newAffiliate], “Already an Affiliate”);`
    */
    function addNewAffilliate(address newAfilliate) external onlyOwner {
        affiliatesCount += 1;
        affiliates[newAfilliate] = true;
        affiliates_.push(newAfilliate);
    }

    receive() external payable {}
}

/*
    So to sum up, the two really serious vulnerabilities are in “joinPonzi” and “buyOwnerRole” 
    functions. Still there is lots of inefficient codes and illogical implementations. 
    */
