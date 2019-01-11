{-# LANGUAGE TupleSections #-}
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
import "cryptonite" Crypto.Hash (Digest)

import Data.Bits
import Control.Monad (unless, when)
import Data.Word (Word8)
import Data.ByteArray (convert)
import Data.Serialize
import Data.List (sort)
import Data.Semigroup (sconcat)
import Data.List.NonEmpty (NonEmpty(..))
import Data.ByteString (ByteString)
import Data.HashMap.Lazy (HashMap)
import Data.HashSet (HashSet)
import Data.Hashable (Hashable(..))

import qualified Data.List.NonEmpty as NE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.HashMap.Strict as Map
import qualified Data.HashSet as Set
import qualified "cryptonite" Crypto.Hash as Crypto


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
                 | CalendarAttestation ByteString
                 deriving (Show, Eq, Ord)

instance Hashable Attestation where
  hashWithSalt salt a =
    case a of
      BitcoinHeaderAttestation i -> hashWithSalt salt (0::Word8, i)
      CalendarAttestation      s -> hashWithSalt salt (1::Word8, s)

instance Hashable Op where
  hashWithSalt salt v = hashWithSalt salt (opTag v)

data Timestamp = Timestamp {
      tsMsg          :: ByteString
    , tsAttestations :: HashSet Attestation
    , tsOps          :: HashMap Op Timestamp
    }
    deriving (Show, Eq, Ord)

eval :: Op -> ByteString -> ByteString
eval op input =
  case op of
    BinOp OpAppend  a     -> input `BS.append` a
    BinOp OpPrepend a     -> a     `BS.append` input
    UnaryOp OpReverse     -> BS.reverse input
    UnaryOp OpHexlify     -> B16.encode input
    CryptoOp OpSHA1       -> convert (Crypto.hash input :: Digest SHA1)
    CryptoOp OpSHA256     -> convert (Crypto.hash input :: Digest SHA256)
    CryptoOp OpRIPEMD160  -> convert (Crypto.hash input :: Digest RIPEMD160)
    CryptoOp OpKECCACK256 -> convert (Crypto.hash input :: Digest Keccak_256)

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

putOpTS :: Putter (Op, Timestamp)
putOpTS (op, ts) = do
  putOp op
  putTimestamp ts

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

append, prepend :: ByteString -> Op
append  = BinOp OpAppend
prepend = BinOp OpPrepend

sha256 :: Op
sha256 = CryptoOp OpSHA256

mkTS :: ByteString -> Timestamp
mkTS msg = Timestamp msg Set.empty Map.empty

mkTSOp :: Timestamp -> Op -> Timestamp
mkTSOp ts op = mkTS (eval op (tsMsg ts))

addTS ts op t = ts { tsOps = Map.insert op t (tsOps ts) }

addOp :: Timestamp -> Op -> (Timestamp, Timestamp)
addOp ts op = (, tsOp) $
    ts { tsOps = Map.insert op tsOp (tsOps ts) }
    where
      tsOp = mkTSOp ts op

addOp' :: Timestamp -> Op -> Timestamp
addOp' ts = fst . addOp ts

catUnary :: Op -> Timestamp -> Timestamp -> Timestamp
catUnary unary left right =
  let
      (_, rs) = addOp right (prepend (tsMsg left))
      (_, ls) = addOp left app
      l       = addTS left app r'
      (r', _) = addOp rs unary
  in
    if ls /= rs then error "stamps should be equal"
                else l
  where
    app = append (tsMsg right)


catSHA256 :: Timestamp -> Timestamp -> Timestamp
catSHA256 = catUnary sha256


testSerialize :: IO ()
testSerialize =
  let
      hash      = BS.replicate 32 0xFE
      ts        = catSHA256 testTimestamp testTimestamp
      serialize = serializeProof OpSHA256 hash ts
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
testTimestamp = ts
    where
      ao op t = fst (addOp t op)
      ts = Timestamp {
             tsMsg = "hello"
           , tsAttestations = Set.singleton testAttestation
           , tsOps = Map.empty
           }
