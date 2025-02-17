// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2015-2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_PUREHEADER_H
#define BITCOIN_PRIMITIVES_PUREHEADER_H

#include "serialize.h"
#include "uint256.h"
#include "hash.h"
#include "util.h"

const int NUM_ALGOS = 4;

enum {
  ALGO_QUARK = 0,
  ALGO_SHA256D = 1,
  ALGO_ARGON2 = 2,
  ALGO_POS = 3
};

enum {
    BLOCK_VERSION_AUXPOW = (1 << 8),
    BLOCK_VERSION_ALGO = (3 << 9),
    BLOCK_VERSION_QUARK = (0 << 9),
    BLOCK_VERSION_SHA256D = (1 << 9),
    BLOCK_VERSION_ARGON2 = (2 << 9),
    BLOCK_VERSION_POS = (3 << 9),
    BLOCK_VERSION_UPDATE_SSF = (1 << 12),
    BLOCK_VERSION_CHAIN = (1 << 16)
};

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CPureBlockHeader
{
public:
    // header
    static const int32_t CURRENT_VERSION=5;
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    uint256 nAccumulatorCheckpoint;
    bool isParent;
    int32_t algoParent;

    CPureBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);

        //zerocoin active, header changes to include accumulator checksum
        if(nVersion > 3 && !isParent)
            READWRITE(nAccumulatorCheckpoint);
    }

    void SetNull()
    {
        nVersion = CPureBlockHeader::CURRENT_VERSION;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        nAccumulatorCheckpoint = 0;
	isParent = false;
	algoParent = -1;
    }

    void SetAlgo(int32_t algo)
    {
	switch(algo)
	    {
	    case ALGO_QUARK:
		nVersion |= BLOCK_VERSION_QUARK;
		break;
	    case ALGO_SHA256D:
		nVersion |= BLOCK_VERSION_SHA256D;
		break;
	    case ALGO_ARGON2:
		nVersion |= BLOCK_VERSION_ARGON2;
		break;
	    case ALGO_POS:
		nVersion |= BLOCK_VERSION_POS;
		break;
	    default:
		break;
	    }
    }

    int32_t GetAlgo () const {
	if (algoParent != -1) return algoParent;
	switch (nVersion & BLOCK_VERSION_ALGO)
	    {
	    case BLOCK_VERSION_QUARK:
		return ALGO_QUARK;
	    case BLOCK_VERSION_SHA256D:
		return ALGO_SHA256D;
	    case BLOCK_VERSION_ARGON2:
		return ALGO_ARGON2;
	    case BLOCK_VERSION_POS:
		return ALGO_POS;
	    }
	return ALGO_QUARK;
    }

  std::string GetAlgoName() const {
    switch (nVersion & BLOCK_VERSION_ALGO)
      {
      case BLOCK_VERSION_QUARK:
	return "QUARK";
      case BLOCK_VERSION_SHA256D:
	return "SHA256D";
      case BLOCK_VERSION_ARGON2:
	return "ARGON2";
      case BLOCK_VERSION_POS:
	return "POS";
      }
    return "QUARK";
  }

    void SetChainId(int32_t id)
    {
	nVersion %= BLOCK_VERSION_CHAIN;
	nVersion |= id * BLOCK_VERSION_CHAIN;
    }
    
    int32_t GetChainId() const
    {
	return nVersion >> 16;
    }

    void SetUpdateSSF()
    {
	nVersion |= BLOCK_VERSION_UPDATE_SSF;
    }
    
    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    uint256 GetPoWHash(int32_t algo) const
    {
	switch(algo) {
	case ALGO_SHA256D:
	  {
	    if (isParent) {
	      return Hash(BEGIN(nVersion),END(nNonce));
	    }
	    else {
	      return Hash(BEGIN(nVersion),END(nAccumulatorCheckpoint));
	    }
	  }
	case ALGO_ARGON2:
	    {
		uint256 thash;
		if (isParent) {
		  hash_argon2(BEGIN(nVersion),BEGIN(thash),80);
		}
		else {
		  hash_argon2(BEGIN(nVersion),BEGIN(thash));
		}
		return thash;
	    }
	case ALGO_POS:
	    return Hash(BEGIN(nVersion), END(nAccumulatorCheckpoint));
	}
	if (nVersion < 4) {
	    return HashQuark(BEGIN(nVersion),END(nNonce));
	}
	else if (nVersion == 4) {
	    return Hash(BEGIN(nVersion), END(nAccumulatorCheckpoint));
	}
	else {
	    return HashQuark(BEGIN(nVersion),END(nAccumulatorCheckpoint));
	}
    }

    uint256 GetPoWHash() const
    {
	return GetPoWHash(GetAlgo());
    }
    
    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    inline void SetAuxpow(bool auxpow)
    {
	if (auxpow)
	    nVersion |= BLOCK_VERSION_AUXPOW;
	else
	    nVersion &= ~BLOCK_VERSION_AUXPOW;
    }
    
    inline bool IsAuxpow() const
    {
	return nVersion & BLOCK_VERSION_AUXPOW;
    }
};

#endif // BITCOIN_PRIMITIVES_PUREHEADER_H
