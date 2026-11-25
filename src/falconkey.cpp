// Copyright (c) 2025 The 42-coin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "falconkey.h"

#include "hash.h"
#include <oqs/oqs.h>

CFalconKeyID CFalconKey::MakeKeyID(const std::vector<unsigned char>& vchPubKey)
{
    if (vchPubKey.size() != FALCON512_PUBKEY_SIZE)
        return CFalconKeyID();

    std::vector<unsigned char, secure_allocator<unsigned char> > vchHashBuffer(32);
    SHA256(&vchPubKey[0], vchPubKey.size(), &vchHashBuffer[0]);

    std::vector<unsigned char> vchHash(vchHashBuffer.begin(), vchHashBuffer.end());
    return CFalconKeyID(uint256(vchHash));
}

CFalconKeyID CFalconKey::GetID() const
{
    return MakeKeyID(vchPubKey);
}

bool CFalconKey::MakeNewKey()
{
    vchPubKey.resize(FALCON512_PUBKEY_SIZE);
    vchPrivKey.resize(FALCON512_PRIVKEY_SIZE);

    if (OQS_SIG_falcon_512_keypair(&vchPubKey[0], &vchPrivKey[0]) != OQS_SUCCESS)
    {
        vchPubKey.clear();
        vchPrivKey.clear();
        fSet = false;
        return false;
    }

    fSet = true;
    return true;
}

bool CFalconKey::SetPrivKey(const CFalconPrivKey& vchPrivKeyIn)
{
    if (vchPrivKeyIn.size() != FALCON512_PRIVKEY_SIZE)
        return false;

    vchPrivKey = vchPrivKeyIn;
    fSet = !vchPubKey.empty() && vchPubKey.size() == FALCON512_PUBKEY_SIZE;
    return fSet;
}

bool CFalconKey::Sign(const uint256& hash, std::vector<unsigned char>& vchSigOut) const
{
    return Sign(hash.begin(), hash.size(), vchSigOut);
}

bool CFalconKey::Sign(const void* pMsg, size_t nMsgLen, std::vector<unsigned char>& vchSigOut) const
{
    vchSigOut.clear();
    if (!IsValid())
        return false;

    vchSigOut.resize(FALCON512_SIG_MAX_SIZE);
    size_t nSigLen = 0;

    if (OQS_SIG_falcon_512_sign(&vchSigOut[0], &nSigLen, (const unsigned char*)pMsg, nMsgLen, &vchPrivKey[0]) != OQS_SUCCESS)
    {
        vchSigOut.clear();
        return false;
    }

    vchSigOut.resize(nSigLen);
    return true;
}

bool CFalconKey::Verify(const std::vector<unsigned char>& vchSig, const void* pMsg, size_t nMsgLen, const std::vector<unsigned char>& vchPubKey)
{
    if (vchPubKey.size() != FALCON512_PUBKEY_SIZE || vchSig.empty() || vchSig.size() > FALCON512_SIG_MAX_SIZE)
        return false;

    // OQS Falcon API is asymmetric: sign() takes (sig, &siglen, msg, msglen, sk)
    // but verify() takes (msg, msglen, sig, siglen, pk) - message goes FIRST.
    return OQS_SIG_falcon_512_verify((const unsigned char*)pMsg, nMsgLen, &vchSig[0], vchSig.size(), &vchPubKey[0]) == OQS_SUCCESS;
}

void CFalconKey::SplitForScript(const std::vector<unsigned char>& vch, std::vector<unsigned char>& vch1, std::vector<unsigned char>& vch2)
{
    vch1.assign(vch.begin(),
                vch.begin() + std::min(vch.size(), (size_t)CHUNK_SIZE));
    vch2.assign(vch.begin() + vch1.size(), vch.end());
}
