{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.OpenTimestamps
    ( serialize
    ) where

import Data.Word (Word8)
import Data.Serialize
import Data.List (sort)
import Data.Semigroup (sconcat)
import Data.List.NonEmpty (NonEmpty)
import Data.ByteString (ByteString)

import qualified Data.List.NonEmpty as NE

data Op = Op ()

data Attestation = BitcoinHeaderAttestation
                 deriving (Eq, Ord)

data Timestamp = Timestamp {
      tsAttestations :: NonEmpty Attestation
    , tsOps          :: [Op]
    }

version :: Word8
version = 0x1

magic :: ByteString
magic = "\x00OpenTimestamps\x00\x00Log\x00\xd9\x19\xc5\x3a\x99\xb1\x12\xe9\xa6\xa1\x00"


putHeader :: Put
putHeader = do
  putByteString magic
  putWord8 version

putAttestation :: Putter Attestation
putAttestation att = error "implement putAttestation"

sep  = putWord8 0xff
atag = putWord8 0x00

amark = sep >> atag


putTimestamp :: Putter Timestamp
putTimestamp Timestamp{..} = do
  let sortedAs    = NE.sort tsAttestations
      sortedOps   = sort tsOps
      putAttests  = NE.map putAttestation sorted
      putAttests' = amark `NE.cons` NE.intersperse sep putAttests
      putOps'     = sep   `NE.cons` NE.intersperse sep putOps
  sconcat putAttests'
  mconcat putOps

serialize :: Putter Timestamp
serialize ots = do
  putHeader
  putTimestamp ots


-- makeMerkleTree :: NonEmpty OpenTimestamp
-- makeMerkleTree stamps =
