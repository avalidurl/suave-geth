// Code generated by suave/gen. DO NOT EDIT.
// Hash: c665a963a4291519f2753cb50b03ac67f3535b73d0372db98840d89e08d47037
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

type CallLog struct {
	Addr   common.Address
	Data   []byte
	Topics [][]byte
}

type CallResult struct {
	ReturnData []byte
	Logs       []*CallLog
}

type Withdrawal struct {
	Index     uint64
	Validator uint64
	Address   common.Address
	Amount    uint64
}
