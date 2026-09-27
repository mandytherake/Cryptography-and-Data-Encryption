pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

template AccountRollup() {
    signal input oldBalanceSender;
    signal input oldBalanceReceiver;
    signal input oldNonceSender;
    signal input amount;
    signal input nonce;
    signal input senderExists;
    signal input receiverExists;
    signal input validAmount;
    signal input senderHasFunds;
    signal input validNonce;

    signal output newBalanceSender;
    signal output newBalanceReceiver;
    signal output newNonceSender;
    signal output stateHash;

    senderExists * (1 - senderExists) === 0;
    receiverExists * (1 - receiverExists) === 0;
    validAmount * (1 - validAmount) === 0;
    senderHasFunds * (1 - senderHasFunds) === 0;
    validNonce * (1 - validNonce) === 0;

    assert(senderExists == 1);
    assert(receiverExists == 1);
    assert(validAmount == 1);
    assert(senderHasFunds == 1);
    assert(validNonce == 1);

    newBalanceSender <-- oldBalanceSender - amount;
    newBalanceReceiver <-- oldBalanceReceiver + amount;
    newNonceSender <-- oldNonceSender + 1;

    newBalanceSender === oldBalanceSender - amount;
    newBalanceReceiver === oldBalanceReceiver + amount;
    newNonceSender === oldNonceSender + 1;

    stateHash <-- Poseidon(4)([oldBalanceSender, oldBalanceReceiver, oldNonceSender, amount]);
    stateHash === Poseidon(4)([oldBalanceSender, oldBalanceReceiver, oldNonceSender, amount]);
}

component main = AccountRollup();