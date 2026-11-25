// Copyright (c) 2025 The 42-coin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "falconverify.h"

#include "falconkey.h"
#include "uint256.h"
#include "script.h"
#include "main.h"

#include <oqs/oqs.h>

#include <algorithm>

uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType);

bool VerifyFalconMessage(const std::vector<unsigned char>& ivchSig,
                         const void* pMsg, size_t nMsgLen,
                         const std::vector<unsigned char>& ivchPubKey)
{
    return CFalconKey::Verify(ivchSig, pMsg, nMsgLen, ivchPubKey);
}

bool VerifyFalconScriptSignature(const std::vector<unsigned char>& ivchKid,
                                 const std::vector<unsigned char>& ivchPubKey,
                                 const std::vector<unsigned char>& ivchSig,
                                 const void* pMsg, size_t nMsgLen)
{
    if (ivchKid.size() != 32)
        return false;
    if (ivchPubKey.size() != FALCON512_PUBKEY_SIZE)
        return false;
    if (ivchSig.empty() || ivchSig.size() > FALCON512_SIG_MAX_SIZE)
        return false;

    CFalconKeyID kidExpected = CFalconKey::MakeKeyID(ivchPubKey);
    std::vector<unsigned char> vchKidExpected(kidExpected.begin(), kidExpected.end());
    if (vchKidExpected != ivchKid)
        return false;

    return CFalconKey::Verify(ivchSig, pMsg, nMsgLen, ivchPubKey);
}

std::string FalconLibVersion()
{
    const char* pszVersion = OQS_version();
    return pszVersion ? std::string(pszVersion) : std::string("unknown");
}

bool SelfTestFalconVerification(std::string& strErrorOut)
{
    strErrorOut.clear();

    static const unsigned char vchMsg[32] = {
        0x42, 0x02, 0x42, 0x02, 0x42, 0x02, 0x42, 0x02,
        0x42, 0x02, 0x42, 0x02, 0x42, 0x02, 0x42, 0x02,
        0x42, 0x02, 0x42, 0x02, 0x42, 0x02, 0x42, 0x02,
        0x42, 0x02, 0x42, 0x02, 0x42, 0x02, 0x42, 0x02
    };

    CFalconKey key;
    if (!key.MakeNewKey())
    {
        strErrorOut = "OQS key generation failed";
        return false;
    }

    const std::vector<unsigned char>& vchPubKey = key.GetPubKey();
    if (!key.IsValid())
    {
        strErrorOut = "generated falcon key is not valid";
        return false;
    }

    CFalconKeyID kid = key.GetID();
    if (kid != CFalconKey::MakeKeyID(key.GetPubKey()))
    {
        strErrorOut = "key id mismatch";
        return false;
    }
    std::vector<unsigned char> vchKid(kid.begin(), kid.end());

    std::vector<unsigned char> vchSig;
    if (!key.Sign(vchMsg, sizeof(vchMsg), vchSig) || vchSig.empty())
    {
        strErrorOut = "OQS signing failed";
        return false;
    }

    if (!VerifyFalconScriptSignature(vchKid, vchPubKey, vchSig, vchMsg, sizeof(vchMsg)))
    {
        strErrorOut = "genuine signature rejected";
        return false;
    }

    std::vector<unsigned char> vchTamperedSig(vchSig);
    vchTamperedSig[0] ^= 0x01;
    if (VerifyFalconScriptSignature(vchKid, vchPubKey, vchTamperedSig, vchMsg, sizeof(vchMsg)))
    {
        strErrorOut = "tampered signature (first byte) accepted";
        return false;
    }

    vchTamperedSig = vchSig;
    vchTamperedSig[vchTamperedSig.size() - 1] ^= 0x80;
    if (VerifyFalconScriptSignature(vchKid, vchPubKey, vchTamperedSig, vchMsg, sizeof(vchMsg)))
    {
        strErrorOut = "tampered signature (last byte) accepted";
        return false;
    }

    std::vector<unsigned char> vchMsgBad(vchMsg, vchMsg + sizeof(vchMsg));
    vchMsgBad[0] ^= 0x01;
    if (VerifyFalconScriptSignature(vchKid, vchPubKey, vchSig, &vchMsgBad[0], vchMsgBad.size()))
    {
        strErrorOut = "signature for a different message accepted";
        return false;
    }

    std::vector<unsigned char> vchKidBad(kid.begin(), kid.end());
    vchKidBad[0] ^= 0x01;
    if (VerifyFalconScriptSignature(vchKidBad, vchPubKey, vchSig, vchMsg, sizeof(vchMsg)))
    {
        strErrorOut = "signature accepted with a mismatched key id";
        return false;
    }

    std::vector<unsigned char> vchPubKeyBad(vchPubKey);
    vchPubKeyBad[0] ^= 0x01;
    if (VerifyFalconScriptSignature(vchKid, vchPubKeyBad, vchSig, vchMsg, sizeof(vchMsg)))
    {
        strErrorOut = "signature accepted with a foreign public key";
        return false;
    }

    if (VerifyFalconScriptSignature(vchKid, vchPubKey, std::vector<unsigned char>(), vchMsg, sizeof(vchMsg)))
    {
        strErrorOut = "empty signature accepted";
        return false;
    }

    // End-to-end round-trip through the real script interpreter: satisfy the
    // strict falcon P2SH template exactly as a spend would.
    CScript scriptRedeem = BuildFalconRedeemScript(kid);
    CScript scriptP2SH;
    scriptP2SH << OP_HASH160 << scriptRedeem.GetID() << OP_EQUAL;

    CTransaction txTo;
    txTo.vin.push_back(CTxIn());
    txTo.vout.push_back(CTxOut(1, scriptP2SH));

    uint256 sighash = SignatureHash(scriptRedeem, txTo, 0, SIGHASH_ALL);
    std::vector<unsigned char> vchTxSig;
    if (!key.Sign(sighash, vchTxSig) || vchTxSig.empty())
    {
        strErrorOut = "script round-trip: signing failed";
        return false;
    }

    std::vector<unsigned char> vchSig1, vchSig2, vchKey1, vchKey2;
    CFalconKey::SplitForScript(vchTxSig, vchSig1, vchSig2);
    CFalconKey::SplitForScript(key.GetPubKey(), vchKey1, vchKey2);
    std::vector<unsigned char> vchRedeem(scriptRedeem.begin(), scriptRedeem.end());

    CScript scriptSig;
    scriptSig << vchSig2 << vchSig1 << vchKey2 << vchKey1 << vchRedeem;
    if (!VerifyScript(scriptSig, scriptP2SH, txTo, 0, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_FALCON, 0))
    {
        strErrorOut = "script round-trip: genuine spend rejected";
        return false;
    }

    std::vector<unsigned char> vchTxSigBad = vchTxSig;
    vchTxSigBad[0] ^= 0x01;
    CFalconKey::SplitForScript(vchTxSigBad, vchSig1, vchSig2);
    CScript scriptSigBad;
    scriptSigBad << vchSig2 << vchSig1 << vchKey2 << vchKey1 << vchRedeem;
    if (VerifyScript(scriptSigBad, scriptP2SH, txTo, 0, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_FALCON, 0))
    {
        strErrorOut = "script round-trip: tampered signature accepted";
        return false;
    }

    // Legacy evaluation: without the falcon flag the spend must still verify
    // (EC compatibility for pre-activation nodes).
    if (!VerifyScript(scriptSig, scriptP2SH, txTo, 0, SCRIPT_VERIFY_P2SH, 0))
    {
        strErrorOut = "script round-trip: legacy (non-falcon) evaluation rejected a valid spend";
        return false;
    }

    return true;
}
