// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2013-2022 The NovaCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef MINER_H
#define MINER_H

#include <memory>

class CBlock;
class CBlockIndex;
class CTransaction;
class CReserveKey;
class CWallet;

/* Generate a new block, without valid proof-of-work/with provided proof-of-stake */
std::shared_ptr<CBlock> CreateNewBlock(CWallet* pwallet, CTransaction *txAdd=nullptr);

/** Modify the extranonce in a block */
void IncrementExtraNonce(std::shared_ptr<CBlock>& pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce);

/** Do mining precalculation */
void FormatHashBuffers(const std::shared_ptr<CBlock>& pblock, char* pmidstate, char* pdata, char* phash1);

/** Check mined proof-of-work block */
bool CheckWork(const std::shared_ptr<CBlock>& pblock, CWallet& wallet, CReserveKey& reservekey);

/** Check mined proof-of-stake block */
bool CheckStake(const std::shared_ptr<CBlock>& pblock, CWallet& wallet);

/** Base sha256 mining transform */
void SHA256Transform(void* pstate, void* pinput, const void* pinit);

/** Stake miner thread */
void ThreadStakeMiner(void* parg);

#endif // MINER_H
