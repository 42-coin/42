#include "kernelrecord.h"

#include "wallet.h"
#include "kernel.h"
#include "base58.h"

using namespace std;

bool KernelRecord::showTransaction(const CWalletTx &wtx)
{
    if (wtx.IsCoinBase())
    {
        if (wtx.GetDepthInMainChain() < 2)
        {
            return false;
        }
    }

    if(!wtx.IsTrusted())
    {
        return false;
    }

    return true;
}

/*
 * Decompose CWallet transaction to model kernel records.
 */
vector<KernelRecord> KernelRecord::decomposeOutput(const CWallet *wallet, const CWalletTx &wtx)
{
    vector<KernelRecord> parts;
    int64_t nTime = wtx.GetTxTime();
    uint256 hash = wtx.GetHash();
    std::map<std::string, std::string> mapValue = wtx.mapValue;
    if (showTransaction(wtx))
    {
        for (unsigned int nOut = 0; nOut < wtx.vout.size(); nOut++)
        {
            CTxOut txOut = wtx.vout[nOut];
            if( wallet->IsMine(txOut) ) {
                CBitcoinAddress addrStore;
                std::string addrStr;

                // keystore-aware extraction: resolves strict falcon redeem
                // scripts into falcon addresses (f...), not legacy "9"
                if (ExtractAddress(*wallet, txOut.scriptPubKey, addrStore))
                {
                    addrStr = addrStore.ToString();
                }
                else
                {
                    CTxDestination address;
                    if (ExtractDestination(txOut.scriptPubKey, address))
                    {
                        // Sent to Bitcoin Address
                        addrStr = CBitcoinAddress(address).ToString();
                    }
                    else
                    {
                        // Sent to IP, or other non-address transaction like OP_EVAL
                        addrStr = mapValue["to"];
                    }
                }

                parts.push_back(KernelRecord(hash, nTime, addrStr, txOut.nValue, wtx.IsSpent(nOut)));
            }
        }
    }

    return parts;
}

std::string KernelRecord::getTxID()
{
    return hash.ToString() + strprintf("-%03d", idx);
}

int64_t KernelRecord::getAge() const
{
    return (GetAdjustedTime() - nTime) / nOneDay;
}

uint64_t KernelRecord::getCoinDay() const
{
    bool fStakeWeightV2 = IsStakeWeightV2(GetAdjustedTime());
    int64_t nMinAge = fStakeWeightV2 ? nStakeMinAgeV2 : nStakeMinAge;
    int64_t nUnit = fStakeWeightV2 ? nOneHour : nOneDay;
    int64_t nWeight = GetAdjustedTime() - nTime - nMinAge;
    if( nWeight <  0)
        return 0;
    nWeight = min(nWeight, (int64_t)nStakeMaxAge);
    uint64_t coinAge = (nValue * nWeight ) / (COIN * nUnit);
    return coinAge;
}

int64_t KernelRecord::getPoSReward(int minutes)
{
    int64_t PoSReward;
    int64_t nMinAge = IsStakeWeightV2(GetAdjustedTime()) ? nStakeMinAgeV2 : nStakeMinAge;
    int64_t nWeight = GetAdjustedTime() - nTime + minutes * 60;
    if( nWeight <  nMinAge)
        return 0;
    uint64_t coinAge = (nValue * nWeight ) / (COIN * nOneDay);
    PoSReward = GetProofOfStakeReward(coinAge);
    return PoSReward;
}

double KernelRecord::getProbToMintStake(double difficulty, int timeOffset) const
{
    //double maxTarget = pow(static_cast<double>(2), 224);
    //double target = maxTarget / difficulty;
    //int dayWeight = (min((GetAdjustedTime() - nTime) + timeOffset, (int64_t)(nStakeMinAge+nStakeMaxAge)) - nStakeMinAge) / 86400;
    //uint64_t coinAge = max(nValue * dayWeight / COIN, (int64_t)0);
    //return target * coinAge / pow(static_cast<double>(2), 256);
    bool fStakeWeightV2 = IsStakeWeightV2(GetAdjustedTime() + timeOffset);
    int64_t nMinAge = fStakeWeightV2 ? nStakeMinAgeV2 : nStakeMinAge;
    int64_t Weight = (min((GetAdjustedTime() - nTime) + timeOffset, (int64_t)(nMinAge+nStakeMaxAge)) - nMinAge);
    // Probability per second, computed exactly like the consensus target of
    // CheckStakeKernelHash(): the kernel weight is value*age in coin-hours
    // (v2) or coin-days (v1), and a kernel hits when
    // hash < weight * nBitsTarget / (2^256 * weightScale). With the standard
    // difficulty definition (target = 2^224 / difficulty) that folds into
    //     P(second) = coinAge / (2^32 * difficulty).
    // This must stay in floating point: the old integer division at coin-day
    // granularity zeroed out fractional stakes - under v2 (min age 1 hour,
    // fractional coin ages) any coin below a full coin-day of weight was
    // displayed as 0% although consensus gives it real weight.
    int64_t nWeightUnit = fStakeWeightV2 ? nOneHour : nOneDay;
    double coinAge = (double)nValue * Weight / ((double)COIN * nWeightUnit);
    return coinAge / (pow(static_cast<double>(2), 32) * difficulty);
}

double KernelRecord::getProbToMintWithinNMinutes(double difficulty, int minutes)
{
    if(difficulty != prevDifficulty || minutes != prevMinutes)
    {
        double prob = 1;
        double p;
        int d = minutes / (60 * 24); // Number of full days
        int m = minutes % (60 * 24); // Number of minutes in the last day
        int i, timeOffset;

        // Probabilities for the first d days
        for(i = 0; i < d; i++)
        {
            timeOffset = i * nOneDay;
            p = pow(1 - getProbToMintStake(difficulty, timeOffset), nOneDay);
            prob *= p;
        }

        // Probability for the m minutes of the last day
        timeOffset = d * nOneDay;
        p = pow(1 - getProbToMintStake(difficulty, timeOffset), 60 * m);
        prob *= p;

        prob = 1 - prob;
        prevProbability = prob;
        prevDifficulty = difficulty;
        prevMinutes = minutes;
    }
    return prevProbability;
}
