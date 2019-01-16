
module OpenTimestamps.Deserialize where

import Data.Serialize

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

