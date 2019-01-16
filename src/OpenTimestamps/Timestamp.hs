{-# LANGUAGE TupleSections #-}
{-# LANGUAGE OverloadedStrings #-}


module OpenTimestamps.Timestamp where


import Data.ByteString (ByteString)
import Data.HashSet (HashSet)
import Data.HashMap.Lazy (HashMap)

import OpenTimestamps.Attestation
import OpenTimestamps.Op

import qualified Data.HashMap.Strict as Map
import qualified Data.HashSet as Set


data Timestamp = Timestamp {
      tsMsg          :: ByteString
    , tsAttestations :: HashSet Attestation
    , tsOps          :: HashMap Op Timestamp
    }
    deriving (Show, Eq, Ord)

version :: Int
version = 0x1

magic :: ByteString
magic = "\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"


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
