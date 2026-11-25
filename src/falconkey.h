// Copyright (c) 2025 The 42-coin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef H_BITCOIN_FALCONKEY
#define H_BITCOIN_FALCONKEY

#include "allocators.h"
#include "serialize.h"
#include "uint256.h"

#include <vector>

/** Falcon-512 (liboqs) sizes */
static const size_t FALCON512_PUBKEY_SIZE = 897;
static const size_t FALCON512_PRIVKEY_SIZE = 1281;
static const size_t FALCON512_SIG_MAX_SIZE = 700;

typedef std::vector<unsigned char, secure_allocator<unsigned char> > CFalconPrivKey;

/** A reference to a CFalconKey: the SHA256 of its serialized public key */
class CFalconKeyID : public uint256
{
public:
    CFalconKeyID() : uint256() {}
    explicit CFalconKeyID(const uint256& in) : uint256(in) {}
};

/** An encapsulated OQS Falcon-512 key (public part plus private part) */
class CFalconKey
{
private:
    std::vector<unsigned char> vchPubKey;
    CFalconPrivKey vchPrivKey;
    bool fSet;

public:
    IMPLEMENT_SERIALIZE(
        READWRITE(vchPubKey);
        READWRITE(vchPrivKey);
        if (fRead) const_cast<CFalconKey*>(this)->fSet = !vchPrivKey.empty() && vchPubKey.size() == FALCON512_PUBKEY_SIZE;
    )

    CFalconKey() : fSet(false) {}

    void Reset()
    {
        vchPubKey.clear();
        vchPrivKey.clear();
        fSet = false;
    }

    bool IsValid() const { return fSet && vchPubKey.size() == FALCON512_PUBKEY_SIZE && vchPrivKey.size() == FALCON512_PRIVKEY_SIZE; }

    bool MakeNewKey();
    bool SetPrivKey(const CFalconPrivKey& vchPrivKeyIn);
    void SetPubKey(const std::vector<unsigned char>& vchPubKeyIn)
    {
        if (vchPubKeyIn.size() == FALCON512_PUBKEY_SIZE)
            vchPubKey = vchPubKeyIn;
        fSet = !vchPrivKey.empty() && vchPubKey.size() == FALCON512_PUBKEY_SIZE;
    }

    const std::vector<unsigned char>& GetPubKey() const { return vchPubKey; }
    CFalconPrivKey GetPrivKey() const { return vchPrivKey; }

    CFalconKeyID GetID() const;
    static CFalconKeyID MakeKeyID(const std::vector<unsigned char>& vchPubKey);

    //! Maximum size of one script element pushed on the stack (matches MAX_SCRIPT_ELEMENT_SIZE in script.h)
    enum { CHUNK_SIZE = 520 };

    //! Split a buffer into two script-pushable chunks of at most CHUNK_SIZE bytes each.
    //! The second chunk is empty when the data fits into the first one.
    //! This is the chunking used by the phoenix falcon scriptSig layout:
    //! the chunks are pushed in reverse order so that concatenation of
    //! stacktop(-2) || stacktop(-3) restores the original buffer.
    static void SplitForScript(const std::vector<unsigned char>& vch, std::vector<unsigned char>& vch1, std::vector<unsigned char>& vch2);

    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSigOut) const;
    bool Sign(const void* pMsg, size_t nMsgLen, std::vector<unsigned char>& vchSigOut) const;
    static bool Verify(const std::vector<unsigned char>& vchSig, const void* pMsg, size_t nMsgLen, const std::vector<unsigned char>& vchPubKey);
};

#endif
