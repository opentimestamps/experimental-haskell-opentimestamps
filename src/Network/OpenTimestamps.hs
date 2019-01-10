{-# LANGUAGE PackageImports #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.OpenTimestamps
    ( serializeProof
    ) where

import "cryptonite" Crypto.Hash.Algorithms
import "cryptonite" Crypto.Hash (Digest, hash)

import Data.Bits
import Control.Monad (unless, when)
import Data.Word (Word8)
import Data.ByteArray (convert)
import Data.Serialize
import Data.List (sort)
import Data.Semigroup (sconcat)
import Data.List.NonEmpty (NonEmpty(..))
import Data.ByteString (ByteString)

import qualified Data.List.NonEmpty as NE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16


data BinOp = OpAppend
           | OpPrepend
           deriving (Show, Eq, Ord)

data CryptoOp = OpSHA1
              | OpSHA256
              | OpRIPEMD160
              | OpKECCACK256
              deriving (Show, Eq, Ord)

data UnaryOp = OpReverse
             | OpHexlify
             deriving (Show, Eq, Ord)

data Op = BinOp BinOp ByteString
        | CryptoOp CryptoOp
        | UnaryOp UnaryOp
        deriving (Show, Eq, Ord)

data Attestation = BitcoinHeaderAttestation Int
                 deriving (Eq, Ord)

data Timestamp = Timestamp {
      tsAttestations :: NonEmpty Attestation
    , tsOps          :: [Op]
    }

eval :: Op -> ByteString -> ByteString
eval op input =
  case op of
    BinOp OpAppend  a     -> input `BS.append` a
    BinOp OpPrepend a     -> a     `BS.append` input
    UnaryOp OpReverse     -> BS.reverse input
    UnaryOp OpHexlify     -> B16.encode input
    CryptoOp OpSHA1       -> convert (hash input :: Digest SHA1)
    CryptoOp OpSHA256     -> convert (hash input :: Digest SHA256)
    CryptoOp OpRIPEMD160  -> convert (hash input :: Digest RIPEMD160)
    CryptoOp OpKECCACK256 -> convert (hash input :: Digest Keccak_256)

version :: Int
version = 0x1

magic :: ByteString
magic = "\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"


putHeader :: Put
putHeader = do
  putByteString magic
  putVarInt version

opTag :: Op -> Word8
opTag (BinOp OpAppend  _)     = 0xF0
opTag (BinOp OpPrepend _)     = 0xF1
opTag (UnaryOp OpReverse)     = 0xF2
opTag (UnaryOp OpHexlify)     = 0xF3
opTag (CryptoOp OpSHA1)       = 0x02
opTag (CryptoOp OpRIPEMD160)  = 0x03
opTag (CryptoOp OpSHA256)     = 0x08
opTag (CryptoOp OpKECCACK256) = 0x67


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



beforeAll :: a -> [a] -> [a]
beforeAll v xs =
  case xs of
    []       -> []
    (x:rest) -> v : x : beforeAll v rest


putVarInt :: Putter Int
putVarInt 0  = putWord8 0x0
putVarInt !n = do
  let n2 = n .&. 0x7f :: Int
      n3 = if n > 0x7f then n2 .|. 0x80 else n2
  putWord8 (fromIntegral n3)
  let next = n `shiftR` 7
  unless (n <= 0x7f || next == 0) (putVarInt next)


getVarInt :: Get Int
getVarInt = go 0 0
  where
    go :: Int -> Int -> Get Int
    go !shft !val = do
      b <- getWord8
      let next = val .|. (fromIntegral b .&. 0x7F) `shiftL` shft
      if (b .&. 0x80) == 0x80
         then go (shft + 7) next
         else return next


putAttestation :: Putter Attestation
putAttestation att =
  case att of
    BitcoinHeaderAttestation i ->
      do putByteString "\x05\x88\x96\x0d\x73\xd7\x19\x01"
         let bytes = runPut (putVarInt i)
         putVarBytes bytes


putTimestamp :: Putter Timestamp
putTimestamp Timestamp{..} = do
  let sortedAs  = NE.sort tsAttestations
      sortedOps =    sort tsOps
      putAs     = NE.map  putAttestation sortedAs
      putOps    =    map  putOp          sortedOps
      putAs'    = amark `NE.cons` NE.intersperse amark putAs
      putOps'   = beforeAll sep putOps
  sconcat putAs'
  mconcat putOps'
  where
    sep   = putWord8 0xff
    amark = sep >> putWord8 0x00

append, prepend :: ByteString -> Op
append  = BinOp OpAppend
prepend = BinOp OpPrepend

sha256 :: Op
sha256 = CryptoOp OpSHA256

-- catSHA256 left right =
--   CryptoOp OpSHA256 (BinOp Op)

testSerialize :: IO ()
testSerialize =
  let
      hash = BS.replicate 32 0xFF
      serialize = serializeProof OpSHA256 hash testTimestamp
  in
    BS.writeFile "/tmp/hello.ots" (runPut serialize)

serializeProof :: CryptoOp -> ByteString -> Putter Timestamp
serializeProof cop hash timestamp = do
  putHeader
  putOp (CryptoOp cop)
  putByteString hash
  putTimestamp timestamp


testAttestation :: Attestation
testAttestation = BitcoinHeaderAttestation 555555


testTimestamp :: Timestamp
testTimestamp =
    Timestamp {
      tsAttestations = testAttestation :| []
    , tsOps = [prepend "hello", append "world"]
    }
