// Copyright (c) 2025 The 42-coin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef H_BITCOIN_FALCONVERIFY
#define H_BITCOIN_FALCONVERIFY

#include <cstddef>
#include <string>
#include <vector>

/**
 * Strict (consensus) verification of a Falcon-512 script signature.
 * ivchKid - SHA256 of the public key, from the redeem script (32 bytes);
 * ivchPubKey - Falcon-512 public key from the scriptSig (897 bytes);
 * ivchSig - Falcon-512 signature from the scriptSig;
 * ivchMsg - the message being signed (serialized sighash, 32 bytes).
 * All encoding checks and the kid/pubkey consistency check are part of verification.
 */
bool VerifyFalconScriptSignature(const std::vector<unsigned char>& ivchKid,
                                 const std::vector<unsigned char>& ivchPubKey,
                                 const std::vector<unsigned char>& ivchSig,
                                 const void* pMsg, size_t nMsgLen);

/**
 * Raw OQS verification, no encoding checks. Used by wallet-level code.
 */
bool VerifyFalconMessage(const std::vector<unsigned char>& ivchSig,
                         const void* pMsg, size_t nMsgLen,
                         const std::vector<unsigned char>& ivchPubKey);

/**
 * Version string of the liboqs build backing consensus falcon verification.
 */
std::string FalconLibVersion();

/**
 * Runtime consensus self-test of the strict falcon verification pipeline:
 * key generation, signing, acceptance of a genuine signature and rejection of
 * tampered signatures, keys and messages. Run at node startup; a false return
 * means the liboqs build must not be trusted for strict falcon verification.
 */
bool SelfTestFalconVerification(std::string& strErrorOut);

#endif
