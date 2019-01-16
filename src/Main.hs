
module Main where

import OpenTimestamps.Serialize
import OpenTimestamps.Deserialize

import qualified Data.ByteString.Base16 as B16

main :: IO ()
main = do
  putStrLn "hello, world"
  let filename = "/tmp/hstest.ots"
  testSerialize filename
  (hash, typ) <- testDeserialize filename
  print (B16.encode hash, typ)
