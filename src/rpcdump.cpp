// Copyright (c) 2009-2012 Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h"
#include "bitcoinrpc.h"
#include "interface.h"
#include "base58.h"
#include "wallet.h"

#define printf OutputDebugStringF

using namespace json_spirit;
using namespace std;

void EnsureWalletIsUnlocked();

class CTxDump
{
public:
    CBlockIndex *pindex;
    int64_t nValue;
    bool fSpent;
    CWalletTx* ptx;
    int nOut;
    CTxDump(CWalletTx* ptx = NULL, int nOut = -1)
    {
        pindex = NULL;
        nValue = 0;
        fSpent = false;
        this->ptx = ptx;
        this->nOut = nOut;
    }
};

Value importprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "importprivkey <42privkey> [label] [rescan=true]\n"
            "Adds a private key (as returned by dumpprivkey) to your wallet.");

    EnsureWalletIsUnlocked();

    string strSecret = params[0].get_str();
    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);

    if (!fGood) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
    if (fWalletUnlockMintOnly) // ppcoin: no importprivkey in mint-only mode
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is unlocked for minting only.");

    CKey key;
    bool fCompressed;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    key.SetSecret(secret, fCompressed);
    CKeyID keyid = key.GetPubKey().GetID();
    CBitcoinAddress addr = CBitcoinAddress(keyid);
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        // Don't throw error in case a key is already there
        if (pwalletMain->HaveKey(keyid))
            return Value::null;

        pwalletMain->mapKeyMetadata[addr].nCreateTime = 1;
        if (!pwalletMain->AddKey(key))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");

        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBookName(addr, strLabel);

        if (fRescan)
        {
            // whenever a key is imported, we need to scan the whole chain
            pwalletMain->nTimeFirstKey = 1; // 0 would be considered 'no value'

            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }
    }

    return Value::null;
}

Value importfalconkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "importfalconkey <42falconkey> [label] [rescan=true]\n"
            "Adds a post-quantum (Falcon-512) private key (as returned by dumpfalconkey) to your wallet\n"
            "and restores the falcon address it backed.");

    EnsureWalletIsUnlocked();

    string strSecret = params[0].get_str();
    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    CBitcoinFalconKey falconSecret;
    if (!falconSecret.SetString(strSecret))
    {
        unsigned int nExpectedDataSize = FALCON512_PUBKEY_SIZE + FALCON512_PRIVKEY_SIZE;
        std::string strDetail;
        if (falconSecret.GetVersion() == 0)
            strDetail = "invalid base58 or broken checksum";
        else if (falconSecret.GetDataSize() != nExpectedDataSize)
            strDetail = strprintf("decoded %d bytes, expected %d - the key is truncated or contains extra characters",
                                  (int)falconSecret.GetDataSize(), (int)nExpectedDataSize);
        else
            strDetail = "key does not pass validation";
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
            strprintf("Invalid falcon key encoding (decoded version byte %d, this wallet expects %d; %s - "
                      "check the key was copied in full, without spaces or line breaks)",
                      falconSecret.GetVersion(),
                      128 + (fTestNet ? CBitcoinAddress::SCRIPT_ADDRESS_FALCON_TEST : CBitcoinAddress::SCRIPT_ADDRESS_FALCON),
                      strDetail.c_str()));
    }

    CFalconKey keyFalcon;
    if (!falconSecret.GetKey(keyFalcon) || !keyFalcon.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");

    if (fWalletUnlockMintOnly) // ppcoin: no importfalconkey in mint-only mode
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is unlocked for minting only.");

    CScript scriptRedeem = BuildFalconRedeemScript(keyFalcon.GetID());
    CBitcoinAddress addr;
    addr.SetFalconScriptID(scriptRedeem.GetID());
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        // Don't throw error in case a key is already there
        if (pwalletMain->HaveFalconKey(keyFalcon.GetID()))
            return addr.ToString();

        if (!pwalletMain->AddCScript(scriptRedeem))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding falcon script to wallet");

        if (!pwalletMain->AddFalconKey(keyFalcon, addr))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding falcon key to wallet");

        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBookName(addr, strLabel);

        if (fRescan)
        {
            // whenever a key is imported, we need to scan the whole chain
            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }
    }

    return addr.ToString();
}

Value importaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "importaddress <address> [label] [rescan=true]\n"
            "Adds an address or script (in hex) that can be watched as if it were in your wallet but cannot be used to spend.");

    CScript script;
    CBitcoinAddress address(params[0].get_str());
    if (address.IsValid()) {
        if (address.IsPair())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "It's senseless to import pubkey pair address.");
        script.SetAddress(address);
    } else if (IsHex(params[0].get_str())) {
        std::vector<unsigned char> data(ParseHex(params[0].get_str()));
        script = CScript(data.begin(), data.end());
    } else
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid 42 address or script");

    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        if (::IsMine(*pwalletMain, script) == MINE_SPENDABLE)
            throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");

        // Don't throw error in case an address is already there
        if (pwalletMain->HaveWatchOnly(script))
            return Value::null;

        pwalletMain->MarkDirty();

        if (address.IsValid())
            pwalletMain->SetAddressBookName(address, strLabel);

        if (!pwalletMain->AddWatchOnly(script))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");

        if (fRescan)
        {
            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }
    }

    return Value::null;
}

Value removeaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "removeaddress 'address'\n"
            "\nRemoves watch-only address or script (in hex) added by importaddress.\n"
            "\nArguments:\n"
            "1. 'address' (string, required) The address\n"
            "\nExamples:\n"
            "\nremoveaddress 4EqHMPgEAf56CQmU6ZWS8Ug4d7N3gsQVQA\n"
            "\nRemove watch-only address 4EqHMPgEAf56CQmU6ZWS8Ug4d7N3gsQVQA\n");

    CScript script;

    CBitcoinAddress address(params[0].get_str());
    if (address.IsValid()) {
        if (address.IsPair())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey pair addresses aren't supported.");
        script.SetAddress(address);
    } else if (IsHex(params[0].get_str())) {
        std::vector<unsigned char> data(ParseHex(params[0].get_str()));
        script = CScript(data.begin(), data.end());
    } else
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address or script");

    if (::IsMine(*pwalletMain, script) == MINE_SPENDABLE)
        throw JSONRPCError(RPC_WALLET_ERROR, "The wallet contains the private key for this address or script - can't remove it");

    if (!pwalletMain->HaveWatchOnly(script))
        throw JSONRPCError(RPC_WALLET_ERROR, "The wallet does not contain this address or script");

    LOCK2(cs_main, pwalletMain->cs_wallet);

    pwalletMain->MarkDirty();

    if (!pwalletMain->RemoveWatchOnly(script))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error removing address from wallet");

    return Value::null;
}

Value importwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "importwallet <filename>\n"
            "Imports keys from a wallet dump file (see dumpwallet)."
            + HelpRequiringPassphrase());

    EnsureWalletIsUnlocked();

    if(!ImportWallet(pwalletMain, params[0].get_str().c_str()))
       throw JSONRPCError(RPC_WALLET_ERROR, "Error adding some keys to wallet");

    return Value::null;
}

Value dumpprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpprivkey <42address>\n"
            "Reveals the private key corresponding to <42address>.");

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();
    CBitcoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid 42 address");
    if (fWalletUnlockMintOnly)
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is unlocked for minting only.");
    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    CSecret vchSecret;
    bool fCompressed;
    if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    return CBitcoinSecret(vchSecret, fCompressed).ToString();
}

Value dumpfalconkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpfalconkey <42falconaddress>\n"
            "Reveals the post-quantum (Falcon-512) private key corresponding to <42falconaddress>.\n"
            "The redeem script is deterministic from the key, so importfalconkey in another\n"
            "wallet reproduces the same address.");

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();
    CBitcoinAddress address;
    if (!address.SetString(strAddress) || !address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid 42 address");
    if (fWalletUnlockMintOnly)
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is unlocked for minting only.");
    CScriptID scriptID;
    if (!address.GetFalconScriptID(scriptID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a falcon script");

    CScript subscript;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    if (!pwalletMain->GetCScript(scriptID, subscript))
        throw JSONRPCError(RPC_WALLET_ERROR, "Redeem script for address " + strAddress + " is not known");

    CFalconKeyID falconKeyID;
    if (!IsStrictFalconScript(subscript, falconKeyID))
        throw JSONRPCError(RPC_WALLET_ERROR, "Address " + strAddress + " is not a strict falcon script");

    CFalconKey keyFalcon;
    if (!pwalletMain->GetFalconKey(falconKeyID, keyFalcon))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");

    return CBitcoinFalconKey(keyFalcon).ToString();
}

Value dumpwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpwallet <filename>\n"
            "Dumps all wallet keys in a human-readable format."
            + HelpRequiringPassphrase());

    EnsureWalletIsUnlocked();

    if(!DumpWallet(pwalletMain, params[0].get_str().c_str() ))
      throw JSONRPCError(RPC_WALLET_ERROR, "Error dumping wallet keys to file");

    return Value::null;
}

Value dumpmalleablekey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error (
            "dumpmalleablekey <Key view>\n"
            "Dump the private and public key pairs, which correspond to provided key view.\n");

    EnsureWalletIsUnlocked();

    CMalleableKey mKey;
    CMalleableKeyView keyView;
    keyView.SetString(params[0].get_str());

    if (!pwalletMain->GetMalleableKey(keyView, mKey))
        throw runtime_error("There is no such item in the wallet");

    Object result;
    result.push_back(Pair("PrivatePair", mKey.ToString()));
    result.push_back(Pair("Address", CBitcoinAddress(mKey.GetMalleablePubKey()).ToString()));

    return result;
}

Value importmalleablekey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error (
            "importmalleablekey <Key data>\n"
            "Imports the private key pair into your wallet.\n");


    EnsureWalletIsUnlocked();

    CMalleableKey mKey;
    bool fSuccess = mKey.SetString(params[0].get_str());

    Object result;

    if (fSuccess)
    {
        fSuccess = pwalletMain->AddKey(mKey);
        result.push_back(Pair("Successful", fSuccess));
        result.push_back(Pair("Address", CBitcoinAddress(mKey.GetMalleablePubKey()).ToString()));
        result.push_back(Pair("KeyView", CMalleableKeyView(mKey).ToString()));
    }
    else
        result.push_back(Pair("Successful", false));

    return result;
}
