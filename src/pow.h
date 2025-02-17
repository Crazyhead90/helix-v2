// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class uint256;
class arith_uint256;

// Define difficulty retarget algorithms
enum DiffMode {
    DIFF_DEFAULT = 0, // Default to invalid 0
    DIFF_BTC = 1,     // Retarget every x blocks (Bitcoin style)
    DIFF_KGW = 2,     // Retarget using Kimoto Gravity Well
    DIFF_DGW = 3,     // Retarget using Dark Gravity Wave v3
};

uint32_t GetAlgoWeight(int algo);
bool onFork(const CBlockIndex* pindex);
CBlockIndex* get_pprev_algo(const CBlockIndex* p, int use_algo);

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, int algo);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, int algo);
bool CheckAuxPowProofOfWork(const CBlockHeader& block, int16_t chainId);
uint256 GetBlockProof(const CBlockIndex& block);

#endif // BITCOIN_POW_H
