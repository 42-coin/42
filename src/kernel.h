// Copyright (c) 2012-2013 The PPCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef PPCOIN_KERNEL_H
#define PPCOIN_KERNEL_H

#include "bignum.h"

class CBlock;
class CBlockIndex;
class CTransaction;
class COutPoint;
class uint256;

extern unsigned int nStakeMaxAge;
extern unsigned int nStakeMinAge;
extern unsigned int nStakeMinAgeV2;

// Protocol switch time of the v2 stake weight rules (coin-hour weight resolution
// and reduced minimum age). 0 keeps the v1 rules forever.
extern unsigned int nStakeWeightV2Time;

inline bool IsStakeWeightV2(unsigned int nTimeTx)
{
    return nStakeWeightV2Time != 0 && nTimeTx >= nStakeWeightV2Time;
}

// Resolution of the v2 stake weight: one weight unit is 1/STAKE_WEIGHT_SCALE
// of a coin-hour, removing the integer quantization of fractional stakes
static const int64_t STAKE_WEIGHT_SCALE = 1000;

inline int64_t GetStakeWeightScale(unsigned int nTimeTx)
{
    return IsStakeWeightV2(nTimeTx) ? STAKE_WEIGHT_SCALE : 1;
}

// ChainDB upgrade time
extern unsigned int nModifierUpgradeTime;

// MODIFIER_INTERVAL: time to elapse before new modifier is computed
extern unsigned int nModifierInterval;

// MODIFIER_INTERVAL_RATIO:
// ratio of group interval length between the last group and the first group
static const int MODIFIER_INTERVAL_RATIO = 3;

// Whether the given block is subject to new modifier protocol
bool IsFixedModifierInterval(unsigned int nTimeBlock);

// Compute the hash modifier for proof-of-stake
bool ComputeNextStakeModifier(const CBlockIndex* pindexCurrent, uint64_t& nStakeModifier, bool& fGeneratedStakeModifier);

// The stake modifier used to hash for a stake kernel is chosen as the stake
// modifier about a selection interval later than the coin generating the kernel
bool GetKernelStakeModifier(uint256 hashBlockFrom, uint64_t& nStakeModifier);

// Check whether stake kernel meets hash target
// Sets hashProofOfStake on success return
bool CheckStakeKernelHash(unsigned int nBits, const CBlock& blockFrom, uint32_t nTxPrevOffset, const CTransaction& txPrev, const COutPoint& prevout, uint32_t nTimeTx, uint256& hashProofOfStake, uint256& targetProofOfStake, bool fPrintProofOfStake=false);

// Scan given kernel for solutions
bool ScanKernelForward(unsigned char *kernel, uint32_t nBits, uint32_t nInputTxTime, int64_t nValueIn, std::pair<uint32_t, uint32_t> &SearchInterval, std::vector<std::pair<uint256, uint32_t> > &solutions);

// Check kernel hash target and coinstake signature
// Sets hashProofOfStake on success return
bool CheckProofOfStake(const CTransaction& tx, unsigned int nBits, uint256& hashProofOfStake, uint256& targetProofOfStake);

// Compute stake weight of an input in coin-day units (v1) or scaled coin-hour
// units (v2, multiplied by STAKE_WEIGHT_SCALE)
CBigNum GetStakeWeightBN(const CBigNum& bnValueIn, int64_t nTimeWeight, unsigned int nTimeTx);

// Get stake modifier checksum
uint32_t GetStakeModifierChecksum(const CBlockIndex* pindex);

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, uint32_t nStakeModifierChecksum);

// Get time weight using supplied timestamps
// The weight rules follow the v2 protocol switch depending on nIntervalEnd
// (kernel timestamp), so nodes agree on the rules without extra context
inline int64_t GetWeight(int64_t nIntervalBeginning, int64_t nIntervalEnd)
{
    int64_t nMinAge = IsStakeWeightV2((unsigned int)nIntervalEnd) ? nStakeMinAgeV2 : nStakeMinAge;

    return std::min(nIntervalEnd - nIntervalBeginning - nMinAge, (int64_t)nStakeMaxAge);
}

#endif // PPCOIN_KERNEL_H
