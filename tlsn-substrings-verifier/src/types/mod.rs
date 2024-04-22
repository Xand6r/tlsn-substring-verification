#![allow(missing_docs)]
use core::hash::Hash;

use alloc::vec::Vec;
use hashbrown::HashMap;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
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
