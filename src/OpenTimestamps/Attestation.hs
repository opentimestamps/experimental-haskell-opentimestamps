
module OpenTimestamps.Attestation
    ( Attestation(..)
    ) where

import Data.Hashable
import Data.Word
import Data.ByteString (ByteString)

data Attestation = BitcoinHeaderAttestation Int
                 | CalendarAttestation ByteString
                 deriving (Show, Eq, Ord)


instance Hashable Attestation where
  hashWithSalt salt a =
    case a of
      BitcoinHeaderAttestation i -> hashWithSalt salt (0::Word8, i)
      CalendarAttestation      s -> hashWithSalt salt (1::Word8, s)

