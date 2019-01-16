
module Main where

import OpenTimestamps.Serialize
import OpenTimestamps.Deserialize

main :: IO ()
main = do
  putStrLn "hello, world"
  testSerialize
  return ()
