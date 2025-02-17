// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2012-2013 The PPCoin developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2017-2018 The Phore developers
// Copyright (c) 2018-2019 The Helix developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "chain.h"
#include "chainparams.h"
#include "main.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"

#include <math.h>

uint32_t GetAlgoWeight(int algo)
{
    unsigned int weight = 1;
    switch (algo)
	{
	case ALGO_QUARK:
	    weight = 10;
	    break;
	case ALGO_ARGON2:
	    weight = 4000000;
	    break;
	}
    return weight;
}

CBlockIndex* get_pprev_algo(const CBlockIndex* p, int use_algo) {
  if (!p) return 0;
  if (!p->onFork()) return 0;
  int algo = -1;
  if (use_algo>=0) {
    algo = use_algo;
  }
  else {
    algo = p->GetBlockAlgo();
  }
  CBlockIndex * pprev = p->pprev;
  while (pprev && pprev->onFork()) {
    int cur_algo = pprev->GetBlockAlgo();
    if (cur_algo == algo) {
      return pprev;
    }
    pprev = pprev->pprev;
  }
  return 0;
}

unsigned int GetNextWorkRequiredMpow(const CBlockIndex* pindexLast, int algo)
{
    const CBlockIndex *BlockLastSolved = pindexLast;
    const CBlockIndex *BlockReading = pindexLast;
    int64_t nActualTimespan = 0;
    int64_t LastBlockTime = 0;
    int64_t PastBlocksMin = 25;
    int64_t PastBlocksMax = 25; // We have same max and min, just using same variables from old code
    int64_t CountBlocks = 0;
    uint256 PastDifficultyAverage;
    uint256 PastDifficultyAveragePrev;
    uint256 LastDifficultyAlgo;
    int64_t time_since_last_algo = -1;
    int64_t LastBlockTimeOtherAlgos = 0;
    unsigned int algoWeight = GetAlgoWeight(algo);

    int resurrectTime = 300*60; // 300 minutes for a PoW algo
    int nInRowSurge = 9;
    int64_t DGWtimespan = 30*60; // 30 min per pow algo
    if (algo == ALGO_POS) {
	resurrectTime = 10*67;
	nInRowSurge = 95;
	DGWtimespan = 67;
    }
    const int nForkHeight = 200; // min fork height

    int lastInRow = 0; // starting from last block from algo to first occurence of another algo
    bool lastInRowDone = false; // once another algo is found, stop the count

    int nInRow = 0; // consecutive sequence of blocks from algo within the 25 block period
    bool nInRowDone = false; // if an island of 9 or more is found, then stop the count

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || BlockLastSolved->nHeight < PastBlocksMin) {
      return uint256(Params().ProofOfWorkLimit()*algoWeight).GetCompact();
    }

    for (int i=0; BlockReading && BlockReading->nHeight >= nForkHeight - 1; i++) {

      if (!BlockReading->onFork()) { // last block before fork
	if(LastBlockTime > 0){
	  nActualTimespan = (LastBlockTime - BlockReading->GetBlockTime());
	}
	if (LastBlockTimeOtherAlgos > 0 && time_since_last_algo == -1) {
	  time_since_last_algo = LastBlockTimeOtherAlgos - BlockReading->GetBlockTime();
	}
	CountBlocks++;
	if (nInRow<nInRowSurge) {
	  nInRow = 0;
	}
	else{
	  nInRowDone = true;
	}
	break;
      }

      if (!LastBlockTimeOtherAlgos) {
	LastBlockTimeOtherAlgos = BlockReading->GetMedianTimePast();
      }
      
      int block_algo = BlockReading->GetBlockAlgo();
      if (block_algo != algo) { // Only consider blocks from same algo
	BlockReading = BlockReading->pprev;
	if (CountBlocks) lastInRowDone = true;
	if (nInRow<nInRowSurge) {
	  nInRow = 0;
	}
	else {
	  nInRowDone = true;
	}
	continue;
      }
      if (!CountBlocks) LastDifficultyAlgo.SetCompact(BlockReading->nBits);

      CountBlocks++;
      if (!nInRowDone) nInRow++;
      if (!lastInRowDone) lastInRow++;

      if(CountBlocks <= PastBlocksMin) {
	if (CountBlocks == 1) {
	  PastDifficultyAverage.SetCompact(BlockReading->nBits);
	  if (LastBlockTimeOtherAlgos > 0) time_since_last_algo = LastBlockTimeOtherAlgos - BlockReading->GetMedianTimePast();
	  LastBlockTime = BlockReading->GetMedianTimePast();
	  if (fDebug) LogPrintf("block time final = %d\n",LastBlockTime);
	}
	else { PastDifficultyAverage = ((PastDifficultyAveragePrev * (CountBlocks-1)) + (uint256().SetCompact(BlockReading->nBits))) / CountBlocks; }
	PastDifficultyAveragePrev = PastDifficultyAverage;
      }
 
      if (BlockReading->pprev == NULL) {
 	assert(BlockReading);
	if(LastBlockTime > 0){
	  nActualTimespan = (LastBlockTime - BlockReading->GetMedianTimePast());
	}
	break;
      }
      if (CountBlocks >= PastBlocksMax) {
	if(LastBlockTime > 0){
	  if (fDebug) LogPrintf("block time initial %d\n",BlockReading->GetMedianTimePast());
	  nActualTimespan = (LastBlockTime - BlockReading->GetMedianTimePast());
	}
	break;
      }
      
      BlockReading = BlockReading->pprev;
    }

    int pastInRow = 0; // if not done counting, count the past blocks in row with algo starting at the boundary and going back
    if ((nInRow && !nInRowDone || lastInRow && !lastInRowDone) && BlockReading) {
      if (fDebug) LogPrintf("nInRow = %d and not done\n",nInRow);
      const CBlockIndex * BlockPast = BlockReading->pprev;
      while (BlockPast) {
	if (BlockPast->GetBlockAlgo()!=algo||!BlockPast->onFork()) {
	  break;
	}
	pastInRow++;
	BlockPast = BlockPast->pprev;
      }
      if (!lastInRowDone) lastInRow += pastInRow;
    }
    
    uint256 bnNew;
    int lastInRowMod = lastInRow%nInRowSurge;
    if (fDebug) LogPrintf("nInRow = %d lastInRow=%d\n",nInRow,lastInRow);
    bool justHadSurge = nInRow>=nInRowSurge || nInRow && pastInRow && (nInRow+pastInRow)>=nInRowSurge && pastInRow%nInRowSurge!=0;
    if (Params().NetworkID() == CBaseChainParams::TESTNET && pindexLast->nHeight > 1232)
	justHadSurge = false;
    if (justHadSurge || time_since_last_algo>resurrectTime) {
      if (fDebug) LogPrintf("bnNew = LastDifficultyAlgo\n");
      bnNew = LastDifficultyAlgo;
    }
    else {
      bnNew = PastDifficultyAverage;
    }
    int64_t _nTargetTimespan = (CountBlocks-1) * DGWtimespan; //16 min target

    int64_t smultiplier = 1;
    bool smultiply = false;
    if (time_since_last_algo > resurrectTime) { //160 min for special retarget
      smultiplier = time_since_last_algo/resurrectTime;
      if (fDebug) LogPrintf("Resurrector activated for algo %d with time_since_last_algo = %d (height %d), smultiplier %d\n",algo,time_since_last_algo,pindexLast->nHeight, smultiplier);
      nActualTimespan = 10*smultiplier*_nTargetTimespan;
      smultiply = true;
    }

    if (fDebug && lastInRow >= nInRowSurge && !lastInRowMod) LogPrintf("activate surge protector\n");
    if (nActualTimespan < _nTargetTimespan/3 || lastInRow >= nInRowSurge && !lastInRowMod)
      nActualTimespan = _nTargetTimespan/3;
    if (nActualTimespan > _nTargetTimespan*3)
      nActualTimespan = smultiplier*_nTargetTimespan*3;
    
    if (CountBlocks >= PastBlocksMin ) {
      if (lastInRow>=nInRowSurge && !lastInRowMod) {
	bnNew /= 3;
      }
      else if (!justHadSurge) {
	  LogPrintf("adjust bnNew to nActualTimespan\n");
	  bnNew *= nActualTimespan;
	  bnNew /= _nTargetTimespan;
      }
    }
    else if (CountBlocks==1) { // first block of algo for fork
      if (fDebug) {
	LogPrintf("CountBlocks = %d\n",CountBlocks);
	LogPrintf("setting nBits to keep continuity of PoS chain\n");
	LogPrintf("scaling wrt block at height %u algo %d\n",BlockReading->nHeight,algo);
      }
      unsigned int weightPOS = GetAlgoWeight(ALGO_POS);
      if (algo == ALGO_POS) {
	bnNew.SetCompact(BlockReading->nBits); //preserve continuity of chain diff for POS
	bnNew *= (60*algoWeight);
	bnNew /= (67*weightPOS); // 9 out of 10 blocks are PoS
      }
      else {
	  LogPrintf("algo not PoS with weight %u\n",algoWeight);
	  bnNew.SetCompact(0x1d00ffff); // for newer algos, use min diff times 128, weighted
	  bnNew *= algoWeight;
	  bnNew /= 128;
	  LogPrintf("did set bnNew to %s\n",bnNew.ToString().c_str());
      }
      if (smultiply) bnNew *= smultiplier*3;
    }
    else {
      if (smultiply) bnNew *= smultiplier*3;
      if (lastInRow>=nInRowSurge && !lastInRowMod) bnNew /= 3;
    }
    
    if (bnNew > Params().ProofOfWorkLimit()*algoWeight) {
	LogPrintf("bnNew > limit\n");
	bnNew = Params().ProofOfWorkLimit()*algoWeight;
    }

    uint256 bnHardLimit = ~uint256(0); // Relevant for testnet
    if (bnNew > bnHardLimit) {
	LogPrintf("bnNew > hardLimit\n");
	bnNew = bnHardLimit;
    }
    
    if (fDebug) {
      LogPrintf("DarkGravityWave RETARGET algo %d\n",algo);
      LogPrintf("_nTargetTimespan = %d    nActualTimespan = %d\n", _nTargetTimespan, nActualTimespan);
      LogPrintf("Before: %08x  %lu\n", pindexLast->nBits,uint256().SetCompact(pindexLast->nBits).ToString());
      LogPrintf("BlockReading: %08x %lu\n",BlockReading->nBits,uint256().SetCompact(BlockReading->nBits).ToString());
      LogPrintf("Avg from past %d: %08x %lu\n", CountBlocks,PastDifficultyAverage.GetCompact(), PastDifficultyAverage.ToString());
      LogPrintf("After:  %08x  %lu\n", bnNew.GetCompact(), bnNew.ToString());
    }

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, int algo)
{
    /* current difficulty formula, helix - DarkGravity v3, written by Evan Duffield - evan@dashpay.io */
    const CBlockIndex* BlockLastSolved = pindexLast;
    const CBlockIndex* BlockReading = pindexLast;
    int64_t nActualTimespan = 0;
    int64_t LastBlockTime = 0;
    int64_t PastBlocksMin = 24;
    int64_t PastBlocksMax = 24;
    int64_t CountBlocks = 0;
    uint256 PastDifficultyAverage;
    uint256 PastDifficultyAveragePrev;

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || BlockLastSolved->nHeight < PastBlocksMin) {
        return Params().ProofOfWorkLimit().GetCompact();
    }

    if (pindexLast->nHeight >= Params().MultiPow_StartHeight()-1) { // Multi-PoW
      return GetNextWorkRequiredMpow(pindexLast,algo);
    }
    
    if (pindexLast->nHeight > Params().LAST_POW_BLOCK()) { // PoS
	
        uint256 bnTargetLimit = (~uint256(0) >> 24);
        int64_t nTargetSpacing = 60;
        int64_t nTargetTimespan = 60 * 40;

        int64_t nActualSpacing = 0;
        if (pindexLast->nHeight != 0)
            nActualSpacing = pindexLast->GetBlockTime() - pindexLast->pprev->GetBlockTime();

        if (nActualSpacing < 0)
            nActualSpacing = 1;

        // ppcoin: target change every block
        // ppcoin: retarget with exponential moving toward target spacing
        uint256 bnNew;
        bnNew.SetCompact(pindexLast->nBits);

        int64_t nInterval = nTargetTimespan / nTargetSpacing;
        bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
        bnNew /= ((nInterval + 1) * nTargetSpacing);

        if (bnNew <= 0 || bnNew > bnTargetLimit)
            bnNew = bnTargetLimit;

        return bnNew.GetCompact();
    }

    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (PastBlocksMax > 0 && i > PastBlocksMax) {
            break;
        }
        CountBlocks++;

        if (CountBlocks <= PastBlocksMin) {
            if (CountBlocks == 1) {
                PastDifficultyAverage.SetCompact(BlockReading->nBits);
            } else {
                PastDifficultyAverage = ((PastDifficultyAveragePrev * CountBlocks) + (uint256().SetCompact(BlockReading->nBits))) / (CountBlocks + 1);
            }
            PastDifficultyAveragePrev = PastDifficultyAverage;
        }

        if (LastBlockTime > 0) {
            int64_t Diff = (LastBlockTime - BlockReading->GetBlockTime());
            nActualTimespan += Diff;
        }
        LastBlockTime = BlockReading->GetBlockTime();

        if (BlockReading->pprev == NULL) {
            assert(BlockReading);
            break;
        }
        BlockReading = BlockReading->pprev;
    }

    uint256 bnNew(PastDifficultyAverage);

    int64_t _nTargetTimespan = CountBlocks * Params().TargetSpacing();

    if (nActualTimespan < _nTargetTimespan / 3)
        nActualTimespan = _nTargetTimespan / 3;
    if (nActualTimespan > _nTargetTimespan * 3)
        nActualTimespan = _nTargetTimespan * 3;

    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= _nTargetTimespan;

    if (bnNew > Params().ProofOfWorkLimit()) {
        bnNew = Params().ProofOfWorkLimit();
    }

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, int algo)
{
    bool fNegative;
    bool fOverflow;
    uint256 bnTarget;

    if (Params().SkipProofOfWorkCheck())
        return true;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    LogPrintf("CheckProofOfWork() nBits %08x bnTarget = %s, limit = %s, limit*weight = %s\n",nBits,bnTarget.ToString().c_str(),Params().ProofOfWorkLimit().ToString().c_str(),(Params().ProofOfWorkLimit()*GetAlgoWeight(algo)).ToString().c_str());
    if (fNegative) LogPrintf("fNegative\n");
    if (fOverflow) LogPrintf("fOverflow\n");

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > Params().ProofOfWorkLimit()*GetAlgoWeight(algo))
        return error("CheckProofOfWork() : nBits below minimum work");

    // Check proof of work matches claimed amount
    if (hash > bnTarget)
         return error("CheckProofOfWork() : hash doesn't match nBits");

    return true;
}

bool CheckAuxPowProofOfWork(const CBlockHeader& block, int16_t chainId)
{
  int algo = block.GetAlgo();
  /*if (block.auxpow || block.IsAuxpow()) {
    LogPrintf("checking auxpowproofofwork for algo %d\n",algo);
    LogPrintf("chain id : %d\n",block.GetChainId());
    }*/

  if (block.nVersion > 3 && block.IsAuxpow() && block.GetChainId() != chainId) {
    //LogPrintf("auxpow err 1\n");
    return error("%s : block does not have our chain ID"
		 " (got %d, expected %d, full nVersion %d)",
		 __func__,
		 block.GetChainId(),
		 chainId,
		 block.nVersion);
  }

  if (!block.pauxpow) {
    if (block.IsAuxpow()) {
      //LogPrintf("auxpow err 2\n");
      return error("%s : no auxpow on block with auxpow version",
		   __func__);
    }

    if (!CheckProofOfWork(block.GetPoWHash(algo), block.nBits,block.GetAlgo())) {
      //LogPrintf("auxpow err 3\n");
      return error("%s : non-AUX proof of work failed", __func__);
    }

    return true;
  }

  if (!block.IsAuxpow()) {
    //LogPrintf("auxpow err 4\n");
    return error("%s : auxpow on block with non-auxpow version", __func__);
  }

  if (algo == ALGO_QUARK) {
    return error("QUARK algo cannot be merge-mined");
  }
  
  if (!block.pauxpow->check(block.GetHash(), block.GetChainId())) {
    //LogPrintf("auxpow err 5\n");
    return error("%s : AUX POW is not valid", __func__);
  }

  if(fDebug)
    {
      uint256 target;
      target.SetCompact(block.nBits);

      LogPrintf("DEBUG: proof-of-work submitted  \n  parent-PoWhash: %s\n  target: %s  bits: %08x \n",
		block.pauxpow->getParentBlockPoWHash(algo).ToString().c_str(),
		target.GetHex().c_str(),
		target.GetCompact());
    }
  
  if (!CheckProofOfWork(block.pauxpow->getParentBlockPoWHash(algo), block.nBits, block.GetAlgo()))
    {
      return error("%s : AUX proof of work failed", __func__);
    }
  
  return true;
}

uint256 GetBlockProof(const CBlockIndex& block)
{
    uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for a uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    unsigned int algo_weight = GetAlgoWeight(block.GetBlockAlgo());
    uint256 weight(algo_weight);
    return (~bnTarget / (bnTarget/weight + 1)) + 1;
}
