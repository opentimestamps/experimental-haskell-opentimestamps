{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}

module OpenTimestamps.Serialize where

import Data.Serialize

import OpenTimestamps.Attestation
import OpenTimestamps.Timestamp
import OpenTimestamps.Op

import Data.Bits
import Control.Monad (unless)
import Data.List (sort)
import Data.ByteString (ByteString)

import qualified Data.HashMap.Strict as Map
import qualified Data.HashSet as Set
import qualified Data.ByteString as BS



putHeader :: Put
putHeader = do
  putByteString magic
  putVarInt version


putVarInt :: Putter Int
putVarInt 0  = putWord8 0x0
putVarInt !n = do
  let n2 = n .&. 0x7f :: Int
      n3 = if n > 0x7f then n2 .|. 0x80 else n2
  putWord8 (fromIntegral n3)
  let next = n `shiftR` 7
  unless (n <= 0x7f || next == 0) (putVarInt next)


putAttestation :: Putter Attestation
putAttestation att =
  case att of
    BitcoinHeaderAttestation i ->
      do putByteString "\x05\x88\x96\x0d\x73\xd7\x19\x01"
         let bytes = runPut (putVarInt i)
         putVarBytes bytes
    CalendarAttestation _cal ->
        error "implement calendar attestation serialization"


putTimestamp :: Putter Timestamp
putTimestamp Timestamp{..} = do
  let sortedAs  = sort (Set.toList tsAttestations)
      sortedOps = sort (Map.toList tsOps)
      putAs     = map  putAttestation sortedAs
      putOps    = map  putOpTS        sortedOps
      putAs'    = beforeAll amark putAs
      putOps'   = beforeAll sep putOps
  mconcat putAs'
  mconcat putOps'
  where
    sep   = putWord8 0xff
    amark = sep >> putWord8 0x00


putOpTS :: Putter (Op, Timestamp)
putOpTS (op, ts) = do
  putOp op
  putTimestamp ts


putVarBytes :: Putter ByteString
putVarBytes bs = do
  putVarInt (BS.length bs)
  putByteString bs


putOp :: Putter Op
putOp op = do
  putWord8 (opTag op)
  case op of
    BinOp _ val -> putVarBytes val
    _           -> return ()


testSerialize :: FilePath -> IO ()
testSerialize filename =
  let
      hash      = BS.replicate 32 0xFE
      ts        = catSHA256 testTimestamp testTimestamp
      serialize = serializeProof OpSHA256 hash ts
  in
    BS.writeFile filename (runPut serialize)


serializeProof :: CryptoOp -> ByteString -> Putter Timestamp
serializeProof cop hash timestamp = do
  putHeader
  putOp (CryptoOp cop)
  putByteString hash
  putTimestamp timestamp



testTimestamp :: Timestamp
testTimestamp = ts
    where
      _ao op t = fst (addOp t op)
      ts = Timestamp {
             tsMsg = "hello"
           , tsAttestations = Set.singleton testAttestation
           , tsOps = Map.empty
           }

testAttestation :: Attestation
testAttestation = BitcoinHeaderAttestation 555555


beforeAll :: a -> [a] -> [a]
beforeAll v xs =
  case xs of
    []       -> []
    (x:rest) -> v : x : beforeAll v rest

