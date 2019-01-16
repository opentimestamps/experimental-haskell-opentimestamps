{-# LANGUAGE BangPatterns #-} 

module OpenTimestamps.Deserialize where

import Control.Monad (guard)
import Data.Serialize
import Data.ByteString (ByteString)
import Data.Bits

import OpenTimestamps.Op
import OpenTimestamps.Timestamp

import qualified Data.ByteString as BS

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
  mmagic <- getByteString (BS.length magic)
  guard (mmagic == magic)
  ver <- fmap fromIntegral getWord8
  guard (version == ver)
  return ver

getVarBytes :: Get ByteString
getVarBytes = do
  len <- getVarInt
  getByteString len

getOp :: Get Op
getOp = do
  tag <- getWord8
  case parseTag tag of
    Nothing -> fail ("unknown tag " ++ show tag)
    Just op -> do bytes <- getVarBytes
                  return (op bytes)

getCryptoOp :: Get CryptoOp
getCryptoOp = do
  tag <- getWord8
  case parseCryptoTag tag of
    Nothing   -> fail ("unknown crypto tag " ++ show tag)
    Just ctag -> return ctag


getDetachedFileHash :: Get (ByteString, CryptoOp)
getDetachedFileHash = do
  _ <- getHeader
  cryptoOp <- getCryptoOp
  dat <- getByteString (cryptoHashLen cryptoOp)
  return (dat, cryptoOp)


testDeserialize :: FilePath -> IO (ByteString, CryptoOp)
testDeserialize fp = do
  proof <- BS.readFile fp
  case runGet getDetachedFileHash proof of
    Left err  -> fail err
    Right res -> return res



