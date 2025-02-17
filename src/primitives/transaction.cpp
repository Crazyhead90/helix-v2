// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2015-2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"
#include "primitives/transaction.h"

#include "chain.h"
#include "hash.h"
#include "main.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "transaction.h"



extern bool GetTransaction(const uint256 &hash, CTransaction &txOut, uint256 &hashBlock, bool fAllowSlow);

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString()/*.substr(0,10)*/, n);
}

std::string COutPoint::ToStringShort() const
{
    return strprintf("%s-%u", hash.ToString().substr(0,64), n);
}

uint256 COutPoint::GetHash()
{
    return Hash(BEGIN(hash), END(hash), BEGIN(n), END(n));
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        if(scriptSig.IsZerocoinSpend())
            str += strprintf(", zerocoinspend %s...", HexStr(scriptSig).substr(0, 25));
        else
            str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", scriptSig.ToString().substr(0,24));
    if (nSequence != std::numeric_limits<unsigned int>::max())
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
    nRounds = -10;
}

bool COutPoint::IsMasternodeReward(const CTransaction* tx) const
{
    if(!tx->IsCoinStake())
        return false;

    return (n == tx->vout.size() - 1) && (tx->vout[1].scriptPubKey != tx->vout[n].scriptPubKey);
}

uint256 CTxOut::GetHash() const
{
    return SerializeHash(*this);
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, scriptPubKey.ToString().substr(0,30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), wit(tx.wit), nLockTime(tx.nLockTime) {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

std::string CMutableTransaction::ToString() const
{
    std::string str;
    str += strprintf("CMutableTransaction(ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

void CTransaction::UpdateHash() const
{
    *const_cast<uint256*>(&hash) = SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::GetWitnessHash() const
{
    return SerializeHash(*this, SER_GETHASH);
}

CTransaction::CTransaction() : hash(), nVersion(CTransaction::CURRENT_VERSION), vin(), vout(), nLockTime(0) { }

CTransaction::CTransaction(const CMutableTransaction &tx) : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), wit(tx.wit), nLockTime(tx.nLockTime) {
    UpdateHash();
}

CTransaction& CTransaction::operator=(const CTransaction &tx) {
    *const_cast<int*>(&nVersion) = tx.nVersion;
    *const_cast<std::vector<CTxIn>*>(&vin) = tx.vin;
    *const_cast<std::vector<CTxOut>*>(&vout) = tx.vout;
    *const_cast<CTxWitness*>(&wit) = tx.wit;
    *const_cast<unsigned int*>(&nLockTime) = tx.nLockTime;
    *const_cast<uint256*>(&hash) = tx.hash;
    return *this;
}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it)
    {
        // Helix: previously MoneyRange() was called here. This has been replaced with negative check and boundary wrap check.
        if (it->nValue < 0)
            throw std::runtime_error("CTransaction::GetValueOut() : value out of range : less than 0");

        if ((nValueOut + it->nValue) < nValueOut)
            throw std::runtime_error("CTransaction::GetValueOut() : value out of range : wraps the int64_t boundary");

        nValueOut += it->nValue;
    }
    return nValueOut;
}

CAmount CTransaction::GetZerocoinMinted() const
{
    for (const CTxOut& txOut : vout) {
        if(!txOut.scriptPubKey.IsZerocoinMint())
            continue;

        return txOut.nValue;
    }

    return  CAmount(0);
}

bool CTransaction::UsesUTXO(const COutPoint out)
{
    for (const CTxIn& in : vin) {
        if (in.prevout == out)
            return true;
    }

    return false;
}

std::list<COutPoint> CTransaction::GetOutPoints() const
{
    std::list<COutPoint> listOutPoints;
    uint256 txHash = GetHash();
    for (unsigned int i = 0; i < vout.size(); i++)
        listOutPoints.emplace_back(COutPoint(txHash, i));
    return listOutPoints;
}

CAmount CTransaction::GetZerocoinSpent() const
{
    if(!IsZerocoinSpend())
        return 0;

    CAmount nValueOut = 0;
    for (const CTxIn& txin : vin) {
        if(!txin.scriptSig.IsZerocoinSpend())
            continue;

        nValueOut += txin.nSequence * COIN;
    }

    return nValueOut;
}

int CTransaction::GetZerocoinMintCount() const
{
    int nCount = 0;
    for (const CTxOut& out : vout) {
        if (out.scriptPubKey.IsZerocoinMint())
            nCount++;
    }
    return nCount;
}

double CTransaction::ComputePriority(double dPriorityInputs, unsigned int nTxSize) const
{
    nTxSize = CalculateModifiedSize(nTxSize);
    if (nTxSize == 0) return 0.0;

    return dPriorityInputs / nTxSize;
}

unsigned int CTransaction::CalculateModifiedSize(unsigned int nTxSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nTxSize == 0)
        nTxSize = (GetTransactionCost(*this) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
    for (std::vector<CTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }
    return nTxSize;
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < wit.vtxinwit.size(); i++)
        str += "    " + wit.vtxinwit[i].scriptWitness.ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

int64_t GetTransactionCost(const CTransaction& tx)
{
    return ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR -1) + ::GetSerializeSize(tx, SER_NETWORK, 0);
}

bool
CAuxPow::check(const uint256& hashAuxBlock, int nChainId) const
{

  //LogPrintf("check auxpow with parentBlock chainId = %d and vChainMerkleBranch size %d and nChainIndex %d\n",parentBlock.GetChainId(),vChainMerkleBranch.size(),nChainIndex);
  
  if (nIndex != 0) {
    //LogPrintf("check auxpow err 1\n");
    return error("AuxPow is not a generate");
  }

  if (parentBlock.GetChainId() == nChainId) {
    //LogPrintf("check auxpow err 2\n");
    return error("Aux POW parent has our chain ID");
  }
  
  if (vChainMerkleBranch.size() > 30) {
    //LogPrintf("check auxpow err 3\n");
    return error("Aux POW chain merkle branch too long");
  }
  //LogPrintf("get nRootHash vChainMerkleBranch size %d\n",vChainMerkleBranch.size());

    // Check that the chain merkle root is in the coinbase
    const uint256 nRootHash = CBlock::CheckMerkleBranch(hashAuxBlock, vChainMerkleBranch, nChainIndex);
    //LogPrintf("create vchRootHash: %s\n",nRootHash.GetHex().c_str());
    std::vector<unsigned char> vchRootHash(nRootHash.begin(), nRootHash.end());
    std::reverse(vchRootHash.begin(), vchRootHash.end()); // correct endian

    uint256 transaction_hash = GetHash();
    //LogPrintf("transaction_hash = %s\n",transaction_hash.GetHex().c_str());
    //LogPrintf("hashBlock = %s\n",hashBlock.GetHex().c_str());
    //LogPrintf("auxpow transaction = %s\n",ToString().c_str());
    //LogPrintf("auxpow transaction_hash = %s\n",transaction_hash.ToString().c_str());
    /*LogPrintf("merklebranch_hash = %s\n",merklebranch_hash.ToString().c_str());
    BOOST_FOREACH(const uint256& otherside, vMerkleBranch)
      {
	LogPrintf("VMerkleBranch hash: %s\n",otherside.GetHex().c_str());
	}*/    
    
    // Check that we are in the parent block merkle tree
    const uint256 merklebranch_hash = CBlock::CheckMerkleBranch(transaction_hash, vMerkleBranch, nIndex);
    if (merklebranch_hash != parentBlock.hashMerkleRoot) {
      //LogPrintf("check auxpow err 4: \n");
      return error("Aux POW merkle root incorrect");
    }
    
    std::vector<unsigned char> script;
    script = vin[0].scriptSig;
    //LogPrintf("script size = %lu\n",script.size());

    // Check that the same work is not submitted twice to our chain.
    //

    std::vector<unsigned char>::iterator pcHead =
    std::search(script.begin(), script.end(), UBEGIN(pchMergedMiningHeader), UEND(pchMergedMiningHeader));
      
    /*LogPrintf("script:\n");
    for (unsigned int i=0;i<script.size();i++) {
      LogPrintf("%02x",script[i]);
    }
    LogPrintf("\n");*/
    
    std::vector<unsigned char>::iterator pc = std::search(script.begin(), script.end(), vchRootHash.begin(), vchRootHash.end());

    if (pc == script.end()) {
      return error("Aux hash not in parent coinbase");
    }

    //LogPrintf("check if multiple headers in coinbase\n");
       
    if (pcHead != script.end()) {
      // Enforce only one chain merkle root by checking that a single instance of the merged
      // mining header exists just before.

      if (script.end() != std::search(pcHead + 1, script.end(), UBEGIN(pchMergedMiningHeader), UEND(pchMergedMiningHeader))) {
	return error("Multiple merged mining headers in coinbase");
	//LogPrintf("check auxpow err 6\n");
      }

      if (pcHead + sizeof(pchMergedMiningHeader) != pc) {
	//LogPrintf("check auxpow err 7\n");
	return error("Merged mining header is not just before chain merkle root");
      }
    } else {
      // For backward compatibility.
      // Enforce only one chain merkle root by checking that it starts early in the coinbase.
      // 8-12 bytes are enough to encode extraNonce and nBits.
      if (pc - script.begin() > 20) {
	//LogPrintf("check auxpow err 8\n");
	return error("Aux POW chain merkle root must start in the first 20 bytes of the parent coinbase");
      }
    }
    
    // Ensure we are at a deterministic point in the merkle leaves by hashing
    // a nonce and our chain ID and comparing to the index.
    //LogPrintf("vchRootHash size = %lu\n",vchRootHash.size());
    pc += vchRootHash.size();
    if (script.end() - pc < 8) {
      //LogPrintf("check auxpow err 9\n");
      return error("Aux POW missing chain merkle tree size and nonce in parent coinbase");
    }

    int nSize;
    memcpy(&nSize, &pc[0], 4);
    const unsigned merkleHeight = vChainMerkleBranch.size();
    if (nSize != (1 << merkleHeight)) {
      //LogPrintf("check auxpow err 10\n");
      return error("Aux POW merkle branch size does not match parent coinbase");
    }

    int nNonce;
    memcpy(&nNonce, &pc[4], 4);
    
    int expectedIndex = getExpectedIndex(nNonce, nChainId, merkleHeight);
    if (nChainIndex != expectedIndex) {
      if (fDebug) LogPrintf("check auxpow err 11: nChainIndex = %d while expectedIndex (%d,%d,%d) = %d\n",nNonce,nChainId,merkleHeight,nChainIndex,expectedIndex);
      return error("Aux POW wrong index");
    }

    return true;
}

int
CAuxPow::getExpectedIndex(int nNonce, int nChainId, unsigned h)
{
    // Choose a pseudo-random slot in the chain merkle tree
    // but have it be fixed for a size/nonce/chain combination.
    //
    // This prevents the same work from being used twice for the
    // same chain while reducing the chance that two chains clash
    // for the same slot.

    unsigned rand = nNonce;
    rand = rand * 1103515245 + 12345;
    rand += nChainId;
    rand = rand * 1103515245 + 12345;

    return rand % (1 << h);
}
