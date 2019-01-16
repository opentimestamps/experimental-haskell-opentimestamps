{-# LANGUAGE PackageImports #-}
{-# LANGUAGE OverloadedStrings #-}

module OpenTimestamps.Op
    ( Op(..)
    , BinOp(..)
    , CryptoOp(..)
    , UnaryOp(..)
    , eval
    , opTag
    , append, prepend, sha256
    , parseTag
    , parseCryptoTag
    ) where

import Data.Hashable
import Data.Word8
import Data.ByteString (ByteString)
import Data.ByteArray (convert)

import "cryptonite" Crypto.Hash.Algorithms
import "cryptonite" Crypto.Hash (Digest)

import qualified "cryptonite" Crypto.Hash as Crypto
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString as BS


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

instance Hashable Op where
  hashWithSalt salt v = hashWithSalt salt (opTag v)


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


opTag :: Op -> Word8
opTag (BinOp OpAppend  _)     = 0xF0
opTag (BinOp OpPrepend _)     = 0xF1
opTag (UnaryOp OpReverse)     = 0xF2
opTag (UnaryOp OpHexlify)     = 0xF3
opTag (CryptoOp OpSHA1)       = 0x02
opTag (CryptoOp OpRIPEMD160)  = 0x03
opTag (CryptoOp OpSHA256)     = 0x08
opTag (CryptoOp OpKECCACK256) = 0x67

parseCryptoTag :: Word8 -> Maybe CryptoOp
parseCryptoTag w8 =
  case w8 of
    0x02 -> Just OpSHA1
    0x03 -> Just OpRIPEMD160
    0x08 -> Just OpSHA256
    0x67 -> Just OpKECCACK256
    _    -> Nothing


parseTag :: Word8 -> Maybe (ByteString -> Op)
parseTag w8 =
  case w8 of
    0xF0   -> Just $ BinOp OpAppend
    0xF1   -> Just $ BinOp OpPrepend
    0xF2   -> Just $ const $ UnaryOp OpReverse
    0xF3   -> Just $ const $ UnaryOp OpHexlify
    crypto -> fmap (const . CryptoOp) (parseCryptoTag crypto)


append, prepend :: ByteString -> Op
append  = BinOp OpAppend
prepend = BinOp OpPrepend


sha256 :: Op
sha256 = CryptoOp OpSHA256

