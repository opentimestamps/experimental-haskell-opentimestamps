
module Main where

import OpenTimestamps.Serialize

main :: IO ()
main = do
  putStrLn "hello, world"
  testSerialize
  return ()
