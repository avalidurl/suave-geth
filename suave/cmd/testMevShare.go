package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	_ "embed"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/suave/e2e"
	"github.com/ethereum/go-ethereum/suave/sdk"
)

var (
	exNodeEthAddr  = common.HexToAddress("03493869959c866713c33669ca118e774a30a0e5")
	exNodeNetAddr  = "https://rpc.rigil.suave.flashbots.net"
	l1NodeNetAdder = "https://eth-goerli.g.alchemy.com/v2/FXjSPpH91SDIgA6ES9TavZauY6NAlOFn"
	// 0x8768Cc1edcbC034E92aDEf905D82da570fCF6C5d
	fundedAccount      = newPrivKeyFromHex("55682bf9a314b0cf8bd5b4425bbebc8282528aed6f27173bc5d3da021e152d9d")
	mevshare_demoAcct1 = newPrivKeyFromHex("2adbd790d4a73a8fa5940ca931ab1df794fffc05b26c403448a13baf880920de")
	mevshare_demoAcct2 = newPrivKeyFromHex("6059dd0e31d1404f24eb85ffa8344317b5413c4f9d4a518713722d9807e44715")
)

func main() {
	mrpc, _ := rpc.Dial(exNodeNetAddr)
	mevmClt := sdk.NewClient(mrpc, fundedAccount.priv, exNodeEthAddr)
	l1rpc, _ := rpc.Dial(l1NodeNetAdder)
	// l1Clt := sdk.NewClient(l1rpc, fundedAccount.priv, exNodeEthAddr)

	var mevShareContract *sdk.Contract
	_ = mevShareContract

	var (
		testAddr1 *privKey
		// testAddr2 *privKey
	)

	var (
		ethTxn1       *types.Transaction
		ethTxnBackrun *types.Transaction
	)

	fundBalance := big.NewInt(100000000)
	var bidId [16]byte

	steps := []step{
		{
			name: "Create and fund test accounts",
			action: func() error {
				testAddr1 = generatePrivKey()
				// testAddr2 = generatePrivKey()
				fmt.Println("- Created test Addresses")

				if err := fundAccount(mevmClt, testAddr1.Address(), fundBalance); err != nil {
					return err
				}
				fmt.Printf("- Funded test account: %s (%s)\n", testAddr1.Address().Hex(), fundBalance.String())

				// craft mev transactions

				// we use the sdk.Client for the Sign function though we only
				// want to sign simple ethereum transactions and not compute requests
				cltAcct1 := sdk.NewClient(l1rpc, mevshare_demoAcct1.priv, common.Address{})
				cltAcct2 := sdk.NewClient(l1rpc, mevshare_demoAcct2.priv, common.Address{})

				// contract on goerli which transfers value sent in to coinbase for testing builders
				targeAddr := common.HexToAddress("0xAA5C331DF478c26e6909181fc306Ea535F0e4CCe")
				funcSig := "df4b5096"
				funcSigBytes, err := hex.DecodeString(funcSig)
				if err != nil {
					fmt.Println("Error decoding function signature:", err)
					return err
				}

				ethTxn1, _ = cltAcct1.SignTxn(&types.LegacyTx{
					To:       &targeAddr,
					Value:    big.NewInt(50000000000000000),
					Gas:      31000,
					GasPrice: big.NewInt(400),
					Data:     funcSigBytes,
				})

				ethTxnBackrun, _ = cltAcct2.SignTxn(&types.LegacyTx{
					To:       &targeAddr,
					Value:    big.NewInt(50000000000000000),
					Gas:      31420,
					GasPrice: big.NewInt(400),
					Data:     funcSigBytes,
				})
				return nil
			},
		},
		{
			name: "Deploy mev-share contract",
			action: func() error {

				constructorArgs, err := mevShareArtifact.Abi.Constructor.Inputs.Pack([]string{"https://rpc-goerli.flashbots.net"})
				if err != nil {
					return nil
				}

				deployCode := mevShareArtifact.Code
				deployCode = append(deployCode, constructorArgs...)
				txnResult, err := sdk.DeployContract(deployCode, mevmClt)
				if err != nil {
					return err
				}
				receipt, err := txnResult.Wait()
				if err != nil {
					return err
				}
				if receipt.Status == 0 {
					return fmt.Errorf("failed to deploy contract")
				}

				fmt.Printf("- Mev share bundle sender contract deployed: %s\n", receipt.ContractAddress)
				mevShareContract = sdk.GetContract(receipt.ContractAddress, mevShareArtifact.Abi, mevmClt)
				return nil
			},
		},
		{
			name: "Send bid",
			action: func() error {
				refundPercent := 10
				bundle := &types.SBundle{
					Txs:             types.Transactions{ethTxn1},
					RevertingHashes: []common.Hash{},
					RefundPercent:   &refundPercent,
				}
				bundleBytes, _ := json.Marshal(bundle)

				// new bid inputs
				var targetBlock hexutil.Uint64
				err := l1rpc.Call(&targetBlock, "eth_blockNumber")
				if err != nil {
					return err
				}
				fmt.Printf("latest goerli block %s", targetBlock)

				allowedPeekers := []common.Address{mevShareContract.Address(), common.HexToAddress("0x0000000000000000000000000000000043200001")}

				confidentialDataBytes, _ := bundleBidContract.Abi.Methods["fetchBidConfidentialBundleData"].Outputs.Pack(bundleBytes)

				txnResult, err := mevShareContract.SendTransaction("newBid", []interface{}{targetBlock + 1, allowedPeekers, []common.Address{}}, confidentialDataBytes)
				if err != nil {
					fmt.Println(decodeRevertMessage(err.Error()))
					return err
				}
				receipt, err := txnResult.Wait()
				if err != nil {
					return err
				}
				if receipt.Status == 0 {
					return fmt.Errorf("failed to send bid")
				}

				bidEvent := &BidEvent{}
				if err := bidEvent.Unpack(receipt.Logs[0]); err != nil {
					return err
				}
				hintEvent := &HintEvent{}
				if err := hintEvent.Unpack(receipt.Logs[1]); err != nil {
					return err
				}
				bidId = bidEvent.BidId

				fmt.Printf("- Bid sent at txn: %s\n", receipt.TxHash.Hex())
				fmt.Printf("- Bid id: %x\n", bidEvent.BidId)

				return nil
			},
		},
		{
			name: "Send backrun",
			action: func() error {
				backRunBundle := &types.SBundle{
					Txs:             types.Transactions{ethTxnBackrun},
					RevertingHashes: []common.Hash{},
				}
				backRunBundleBytes, _ := json.Marshal(backRunBundle)

				confidentialDataMatchBytes, _ := bundleBidContract.Abi.Methods["fetchBidConfidentialBundleData"].Outputs.Pack(backRunBundleBytes)

				// backrun inputs
				var targetBlock hexutil.Uint64
				err := l1rpc.Call(&targetBlock, "eth_blockNumber")
				if err != nil {
					return err
				}
				fmt.Printf("latest goerli block %s", targetBlock)
				allowedPeekers := []common.Address{mevShareContract.Address(), common.HexToAddress("0x0000000000000000000000000000000043200001")}

				txnResult, err := mevShareContract.SendTransaction("newMatchBundleSender", []interface{}{targetBlock + 1, allowedPeekers, []common.Address{}, bidId}, confidentialDataMatchBytes)
				if err != nil {
					// fmt.Println(decodeRevertMessage(err.Error()))
					return err
				}
				receipt, err := txnResult.Wait()
				if err != nil {
					return err
				}
				if receipt.Status == 0 {
					return fmt.Errorf("failed to send bid")
				}

				debugBundle := &DebugBundleEvent{}
				if err := debugBundle.Unpack(receipt.Logs[0]); err != nil {
					return err
				}
				fmt.Println()
				fmt.Println("debugBundle", debugBundle)

				bidEvent := &BidEvent{}
				if err := bidEvent.Unpack(receipt.Logs[1]); err != nil {
					return err
				}

				fmt.Printf("- Backrun sent at txn: %s\n", receipt.TxHash.Hex())
				// fmt.Printf("- Backrun bid id: %x\n", bidEvent.BidId)
				fmt.Printf("- Backrun num logs: %x\n", len(receipt.Logs))

				return nil
			},
		},
	}

	for indx, step := range steps {
		fmt.Printf("Step %d: %s\n", indx, step.name)
		if err := step.action(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	}
}

func fundAccount(clt *sdk.Client, to common.Address, value *big.Int) error {
	txn := &types.LegacyTx{
		Value: value,
		To:    &to,
	}
	fmt.Println("- created tx")
	result, err := clt.SendTransaction(txn)
	if err != nil {
		return err
	}
	fmt.Println("- sent tx")
	_, err = result.Wait()
	if err != nil {
		return err
	}
	// check balance
	balance, err := clt.RPC().BalanceAt(context.Background(), to, nil)
	if err != nil {
		return err
	}
	if balance.Cmp(value) != 0 {
		return fmt.Errorf("failed to fund account")
	}
	return nil
}

type step struct {
	name   string
	action func() error
}

type privKey struct {
	priv *ecdsa.PrivateKey
}

func (p *privKey) Address() common.Address {
	return crypto.PubkeyToAddress(p.priv.PublicKey)
}

func (p *privKey) MarshalPrivKey() []byte {
	return crypto.FromECDSA(p.priv)
}

func newPrivKeyFromHex(hex string) *privKey {
	key, err := crypto.HexToECDSA(hex)
	if err != nil {
		panic(fmt.Sprintf("failed to parse private key: %v", err))
	}
	return &privKey{priv: key}
}

func generatePrivKey() *privKey {
	key, err := crypto.GenerateKey()
	if err != nil {
		panic(fmt.Sprintf("failed to generate private key: %v", err))
	}
	return &privKey{priv: key}
}

type HintEvent struct {
	BidId [16]byte
	Hint  []byte
}

func (h *HintEvent) Unpack(log *types.Log) error {
	unpacked, err := mevShareArtifact.Abi.Events["HintEvent"].Inputs.Unpack(log.Data)
	if err != nil {
		return err
	}
	h.BidId = unpacked[0].([16]byte)
	h.Hint = unpacked[1].([]byte)
	return nil
}

type BidEvent struct {
	BidId               [16]byte
	DecryptionCondition uint64
	AllowedPeekers      []common.Address
}

func (b *BidEvent) Unpack(log *types.Log) error {
	unpacked, err := bundleBidContract.Abi.Events["BidEvent"].Inputs.Unpack(log.Data)
	if err != nil {
		return err
	}
	b.BidId = unpacked[0].([16]byte)
	b.DecryptionCondition = unpacked[1].(uint64)
	b.AllowedPeekers = unpacked[2].([]common.Address)
	return nil
}

var (
	// bundleBidContract = e2e.MevShareBidContract
	// mevShareArtifact  = e2e.MevShareBundleSenderContract
	bundleBidContract = e2e.BundleBidContract
	mevShareArtifact  = e2e.MevShareBundleSenderContract
)

type DebugBundleEvent struct {
	Bundle types.SBundle
}

func (d *DebugBundleEvent) Unpack(log *types.Log) error {
	unpacked, err := e2e.MevShareBundleSenderContract.Abi.Events["DebugBundleData"].Inputs.Unpack(log.Data)
	if err != nil {
		return err
	}

	var matchBundle types.SBundle
	if err := json.Unmarshal(unpacked[0].([]byte), &matchBundle); err != nil {
		return fmt.Errorf("could not unmarshal mevshare bundle: %w", err)
	}
	d.Bundle = matchBundle
	return nil
}

func decodeRevertMessage(input string) string {
	// remove 0x prefix if exists
	if strings.HasPrefix(input, "0x") {
		input = input[2:]
	}
	// The first 8 characters are the method ID for "Error(string)".
	// The next 64 characters represent the length of the string.
	// The actual message starts after the first 136 characters
	data, err := hex.DecodeString(input[136:])
	if err != nil {
		return fmt.Sprintf("Failed to decode revert reason: %v", err)
	}
	return string(data)
}
