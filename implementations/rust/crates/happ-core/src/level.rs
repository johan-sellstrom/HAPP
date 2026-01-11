use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum PoHpLevel {
    #[serde(rename = "AAIF-PoHP-1")]
    L1,
    #[serde(rename = "AAIF-PoHP-2")]
    L2,
    #[serde(rename = "AAIF-PoHP-3")]
    L3,
    #[serde(rename = "AAIF-PoHP-4")]
    L4,
}

impl PoHpLevel {
    pub fn as_u8(&self) -> u8 {
        match self {
            PoHpLevel::L1 => 1,
            PoHpLevel::L2 => 2,
            PoHpLevel::L3 => 3,
            PoHpLevel::L4 => 4,
        }
    }

    pub fn meets_minimum(&self, min: &PoHpLevel) -> bool {
        self.as_u8() >= min.as_u8()
    }
}

impl fmt::Display for PoHpLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            PoHpLevel::L1 => "AAIF-PoHP-1",
            PoHpLevel::L2 => "AAIF-PoHP-2",
            PoHpLevel::L3 => "AAIF-PoHP-3",
            PoHpLevel::L4 => "AAIF-PoHP-4",
        };
        write!(f, "{s}")
    }
}

impl PartialOrd for PoHpLevel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.as_u8().partial_cmp(&other.as_u8())
    }
}

impl Ord for PoHpLevel {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_u8().cmp(&other.as_u8())
    }
}
