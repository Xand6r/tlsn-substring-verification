use std::{collections::HashMap as StdHashMap, hash::Hash};

use serde::{Deserialize, Serialize};
use tlsn_core::{
    commitment::{CommitmentId, CommitmentInfo, CommitmentOpening},
    merkle::MerkleProof,
};

/// A substring proof containing the commitment openings and a proof
/// that the corresponding commitments are present in the merkle tree.
use hashbrown::HashMap;
use serde::ser::SerializeSeq;

#[derive(Clone, Debug)]
pub struct CustomHashMap<K, V>(pub HashMap<K, V>);

// Implement methods for CustomHashMap
impl<K, V> CustomHashMap<K, V>
where
    K: Serialize + Eq + Hash,
    V: Serialize,
{
    // Example method: insert
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.0.insert(key, value)
    }

    // Example method: get
    pub fn get(&self, key: &K) -> Option<&V> {
        self.0.get(key)
    }
}

// Implement traits for CustomHashMap
impl<K, V> Serialize for CustomHashMap<K, V>
where
    K: Serialize + Eq + Hash,
    V: Serialize,
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Serialize the HashMap as a sequence of key-value pairs
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            let kv = (key, value);
            seq.serialize_element(&kv)?;
        }
        seq.end()
    }
}

impl<'de, K, V> Deserialize<'de> for CustomHashMap<K, V>
where
    K: Deserialize<'de> + Eq + Hash,
    V: Deserialize<'de>,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let vec: Vec<(K, V)> = Deserialize::deserialize(deserializer)?;
        let inner_map: HashMap<K, V> = vec.into_iter().collect();
        Ok(CustomHashMap(inner_map))
    }
}

// Implement conversion from CustomHashMap to HashMap
impl<K, V> From<CustomHashMap<K, V>> for HashMap<K, V> {
    fn from(my_map: CustomHashMap<K, V>) -> Self {
        my_map.0
    }
}

// Implement conversion from HashMap to CustomHashMap
impl<K, V> From<HashMap<K, V>> for CustomHashMap<K, V> {
    fn from(hashmap: HashMap<K, V>) -> Self {
        CustomHashMap(hashmap)
    }
}

pub type PublicHashMap = StdHashMap<CommitmentId, (CommitmentInfo, CommitmentOpening)>;
pub type OpeningsHashMap = HashMap<CommitmentId, (CommitmentInfo, CommitmentOpening)>;

pub fn convert_hashmap_from_std_to_brown(public_map: PublicHashMap) -> OpeningsHashMap {
    let mut openings_map: OpeningsHashMap = OpeningsHashMap::new();

    for (key, value) in public_map {
        openings_map.insert(key, value);
    }

    openings_map
}

pub type CustomOpeningHashMap = CustomHashMap<CommitmentId, (CommitmentInfo, CommitmentOpening)>;

/// A guest substring proof containing the commitment openings and a proof
/// that the corresponding commitments are present in the merkle tree.
#[derive(Serialize, Deserialize)]
pub struct GuestSubstringsProof {
    pub openings: CustomOpeningHashMap,
    pub inclusion_proof: MerkleProof,
}

/// A substring proof containing the commitment openings and a proof
/// that the corresponding commitments are present in the merkle tree.
#[derive(Serialize, Deserialize)]
pub struct PublicSubstringsProof {
    pub openings: PublicHashMap,
    pub inclusion_proof: MerkleProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_serialization_deserialization() {
        let mut new_map = CustomHashMap(HashMap::new());

        new_map.insert("one".to_string(), "1".to_string());
        new_map.insert("two".to_string(), "2".to_string());
        new_map.insert("three".to_string(), "3".to_string());

        // print it
        println!("{:?}", new_map);

        // serialize it
        let serialized_map = serde_json::to_string(&new_map).expect("Serialization failed");
        println!("{:}", serialized_map);

        // deserialize it
        let deserialized_map: CustomHashMap<String, String> =
            serde_json::from_str(&serialized_map).expect("Deserialization failed");

        assert_eq!(
            new_map.get(&"one".to_string()),
            deserialized_map.get(&"one".to_string())
        );
        assert_eq!(
            new_map.get(&"two".to_string()),
            deserialized_map.get(&"two".to_string())
        );
        assert_eq!(
            new_map.get(&"three".to_string()),
            deserialized_map.get(&"three".to_string())
        );
    }
}
