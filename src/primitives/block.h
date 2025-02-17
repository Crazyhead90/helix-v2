// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2015-2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include "primitives/pureheader.h"
#include "primitives/transaction.h"
#include "keystore.h"

/** The maximum allowed size for a serialized block, in bytes (network rule) */
static const unsigned int MAX_BLOCK_SIZE_CURRENT = 2000000;
static const unsigned int MAX_BLOCK_SIZE_LEGACY = 1000000;

class CBlockHeader : public CPureBlockHeader
{
public:
    boost::shared_ptr<CAuxPow> pauxpow;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
	READWRITE(*(CPureBlockHeader*)this);
	if (this->IsAuxpow()) {
	  if (ser_action.ForRead()) {
	    pauxpow.reset(new CAuxPow());
	  }
	  assert(pauxpow);
	  (*pauxpow).parentBlock.isParent = true;
	  int algo = CPureBlockHeader::GetAlgo();
	  (*pauxpow).parentBlock.algoParent = algo;
	  READWRITE(*pauxpow);
	}
	else if (ser_action.ForRead()) {
	  pauxpow.reset();
	}
    }

        void SetNull()
    {
      CPureBlockHeader::SetNull();
      pauxpow.reset();
    }
    
    void SetAuxpow(CAuxPow* apow)
    {
      if (apow)
	{
	  int algo = GetAlgo();
	  apow->parentBlock.isParent = true;
	  apow->parentBlock.algoParent = algo;
	  pauxpow.reset(apow);
	  CPureBlockHeader::SetAuxpow(true);
	} else
	{
	  pauxpow.reset();
	  CPureBlockHeader::SetAuxpow(false);
	}
    }

    void SetAuxpow(bool apow)
    {
      CPureBlockHeader::SetAuxpow(apow);
    }
};

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransaction> vtx;

    // ppcoin: block signature - signed by one of the coin base txout[N]'s owner
    std::vector<unsigned char> vchBlockSig;

    // memory only
    mutable CScript payee;
    mutable std::vector<uint256> vMerkleTree;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(*(CBlockHeader*)this);
        READWRITE(vtx);
	if(vtx.size() > 1 && vtx[1].IsCoinStake())
		READWRITE(vchBlockSig);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        vMerkleTree.clear();
        payee = CScript();
        vchBlockSig.clear();
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.nAccumulatorCheckpoint = nAccumulatorCheckpoint;
	block.pauxpow = pauxpow;
        return block;
    }

    // ppcoin: two types of block: proof-of-work or proof-of-stake
    bool IsProofOfStake() const
    {
	if (nVersion > 4 && CPureBlockHeader::GetAlgo()!=ALGO_POS)
	    return false;
        return (vtx.size() > 1 && vtx[1].IsCoinStake());
    }

    bool IsProofOfWork() const
    {
        return !IsProofOfStake();
    }

    bool SignBlock(const CKeyStore& keystore);
    bool CheckBlockSignature() const;

    std::pair<COutPoint, unsigned int> GetProofOfStake() const
    {
        return IsProofOfStake()? std::make_pair(vtx[1].vin[0].prevout, nTime) : std::make_pair(COutPoint(), (unsigned int)0);
    }

    // Build the in-memory merkle tree for this block and return the merkle root.
    // If non-NULL, *mutated is set to whether mutation was detected in the merkle
    // tree (a duplication of transactions in the block leading to an identical
    // merkle root).
    uint256 BuildMerkleTree(bool* mutated = NULL) const;

    std::vector<uint256> GetMerkleBranch(int nIndex) const;
    static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex);
    std::string ToString() const;
    void print() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull()
    {
        return vHave.empty();
    }
};

/** Compute the consensus-critical block cost (see BIP 141). */
int64_t GetBlockCost(const CBlock& tx);

#endif // BITCOIN_PRIMITIVES_BLOCK_H
