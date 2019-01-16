{-# LANGUAGE BangPatterns #-} 

module OpenTimestamps.Deserialize where

import Control.Monad (guard)
import Data.Serialize
import Data.ByteString (ByteString)
import Data.Bits

import OpenTimestamps.Op
import OpenTimestamps.Timestamp

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


cryptoHashLen :: CryptoOp -> Int
cryptoHashLen OpSHA256     = 32
cryptoHashLen OpKECCACK256 = 32
cryptoHashLen OpRIPEMD160  = 20
cryptoHashLen OpSHA1       = 20

getHeader :: Get Int
getHeader = do
  mmagic <- getByteString (length magic)
  guard (mmagic == magic)
  ver <- getWord8
  guard (version == ver)

getOp :: Get Op
getOp = do
  tag <- getWord8
  case tag of
    BinOp _ val -> putVarBytes val


getDetachedFileHash :: Get (ByteString, CryptoOp)
getDetachedFileHash = do
  getHeader
  cryptoOp <- getOp
  getByteString (cryptoHashLen cryptoOp)
