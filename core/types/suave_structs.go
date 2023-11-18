// Code generated by suave/gen. DO NOT EDIT.
// Hash: 7af8984494440a55af9b08542b6d6a89339279057ee4e165489374bab819dcc9
package types

import "github.com/ethereum/go-ethereum/common"

type BidId [16]byte

// Structs

type Bid struct {
	Id                  BidId
	Salt                BidId
	DecryptionCondition uint64
	AllowedPeekers      []common.Address
	AllowedStores       []common.Address
	Version             string
}

type BuildBlockArgs struct {
	Slot           uint64
	ProposerPubkey []byte
	Parent         common.Hash
	Timestamp      uint64
	FeeRecipient   common.Address
	GasLimit       uint64
	Random         common.Hash
	Withdrawals    []*Withdrawal
}

type Withdrawal struct {
	Index     uint64
	Validator uint64
	Address   common.Address
	Amount    uint64
}
