use std::collections::{HashMap, HashSet, VecDeque};

use ed25519_dalek::Signature;

use mycelium_protocol::types::NodeId;

use crate::identity::{verify_signature, Identity};

/// A signed vouching statement: "I vouch for <vouchee> as <display_name>".
#[derive(Debug, Clone)]
pub struct Vouch {
    pub voucher_id: NodeId,
    pub voucher_public_key: [u8; 32],
    pub vouchee_id: NodeId,
    pub display_name: String,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

impl Vouch {
    /// Create a new vouch, signed by the voucher's identity.
    pub fn create(
        voucher: &Identity,
        vouchee_id: NodeId,
        _vouchee_public_key: &[u8; 32],
        display_name: &str,
        timestamp: u64,
    ) -> Self {
        let voucher_id = voucher.node_id();
        let message = Self::signing_message(&voucher_id, &vouchee_id, display_name, timestamp);
        let signature = voucher.sign(&message);

        Self {
            voucher_id,
            voucher_public_key: voucher.public_key_bytes(),
            vouchee_id,
            display_name: display_name.to_string(),
            signature: signature.to_bytes().to_vec(),
            timestamp,
        }
    }

    /// Verify the vouch signature.
    pub fn verify(&self) -> bool {
        let message = Self::signing_message(
            &self.voucher_id,
            &self.vouchee_id,
            &self.display_name,
            self.timestamp,
        );
        if self.signature.len() != 64 {
            return false;
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature);
        let Ok(signature) = Signature::from_slice(&sig_bytes) else {
            return false;
        };
        verify_signature(&self.voucher_public_key, &message, &signature).is_ok()
    }

    fn signing_message(
        voucher_id: &NodeId,
        vouchee_id: &NodeId,
        display_name: &str,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"mycelium-vouch-v1:");
        msg.extend_from_slice(voucher_id.as_bytes());
        msg.extend_from_slice(vouchee_id.as_bytes());
        msg.extend_from_slice(display_name.as_bytes());
        msg.extend_from_slice(&timestamp.to_le_bytes());
        msg
    }
}

/// Trust score derived from Web of Trust graph traversal.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct TrustScore {
    /// Trust value between 0.0 (no trust) and 1.0 (direct vouch).
    pub value: f32,
    /// Number of hops in the shortest trust path.
    pub hops: u8,
}

impl TrustScore {
    pub const NONE: Self = Self {
        value: 0.0,
        hops: u8::MAX,
    };

    pub const DIRECT: Self = Self {
        value: 1.0,
        hops: 1,
    };
}

/// Trust graph implementing BFS-based trust score computation with decay.
///
/// Trust decays by 0.5 per hop: 1-hop=1.0, 2-hop=0.5, 3-hop=0.25, etc.
pub struct TrustGraph {
    /// Adjacency list: voucher -> set of vouchees
    vouches: HashMap<NodeId, HashSet<NodeId>>,
    /// Reverse lookup: vouchee -> set of vouchers
    vouched_by: HashMap<NodeId, HashSet<NodeId>>,
    /// Max hops to traverse.
    max_hops: u8,
}

impl TrustGraph {
    pub fn new() -> Self {
        Self {
            vouches: HashMap::new(),
            vouched_by: HashMap::new(),
            max_hops: 4,
        }
    }

    pub fn with_max_hops(max_hops: u8) -> Self {
        Self {
            vouches: HashMap::new(),
            vouched_by: HashMap::new(),
            max_hops,
        }
    }

    /// Add a vouch to the graph.
    pub fn add_vouch(&mut self, voucher: NodeId, vouchee: NodeId) {
        self.vouches.entry(voucher).or_default().insert(vouchee);
        self.vouched_by.entry(vouchee).or_default().insert(voucher);
    }

    /// Remove a vouch from the graph.
    pub fn remove_vouch(&mut self, voucher: &NodeId, vouchee: &NodeId) {
        if let Some(set) = self.vouches.get_mut(voucher) {
            set.remove(vouchee);
        }
        if let Some(set) = self.vouched_by.get_mut(vouchee) {
            set.remove(voucher);
        }
    }

    /// Compute the trust score from `from` to `to` using BFS with decay.
    ///
    /// Trust decays: 1-hop = 1.0, 2-hop = 0.5, 3-hop = 0.25, 4-hop = 0.125
    pub fn trust_score(&self, from: &NodeId, to: &NodeId) -> TrustScore {
        if from == to {
            return TrustScore {
                value: 1.0,
                hops: 0,
            };
        }

        let mut visited = HashSet::new();
        visited.insert(*from);

        let mut queue = VecDeque::new();

        // Start with nodes directly vouched by `from`
        if let Some(direct) = self.vouches.get(from) {
            for node in direct {
                if !visited.contains(node) {
                    visited.insert(*node);
                    queue.push_back((*node, 1u8));
                }
            }
        }

        while let Some((current, hops)) = queue.pop_front() {
            if hops > self.max_hops {
                break;
            }

            if current == *to {
                let value = 0.5_f32.powi((hops as i32) - 1);
                return TrustScore { value, hops };
            }

            if let Some(neighbors) = self.vouches.get(&current) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        visited.insert(*neighbor);
                        queue.push_back((*neighbor, hops + 1));
                    }
                }
            }
        }

        TrustScore::NONE
    }

    /// Get all nodes directly vouched by a given node.
    pub fn vouched_by_node(&self, node: &NodeId) -> Vec<NodeId> {
        self.vouches
            .get(node)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get all nodes that have vouched for a given node.
    pub fn vouchers_of(&self, node: &NodeId) -> Vec<NodeId> {
        self.vouched_by
            .get(node)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get the shortest trust path from `from` to `to`.
    pub fn trust_path(&self, from: &NodeId, to: &NodeId) -> Option<Vec<NodeId>> {
        if from == to {
            return Some(vec![*from]);
        }

        let mut visited = HashMap::new();
        visited.insert(*from, *from); // parent map

        let mut queue = VecDeque::new();

        if let Some(direct) = self.vouches.get(from) {
            for node in direct {
                if !visited.contains_key(node) {
                    visited.insert(*node, *from);
                    queue.push_back((*node, 1u8));
                }
            }
        }

        while let Some((current, hops)) = queue.pop_front() {
            if hops > self.max_hops {
                break;
            }

            if current == *to {
                // Reconstruct path
                let mut path = vec![current];
                let mut node = current;
                while node != *from {
                    node = visited[&node];
                    path.push(node);
                }
                path.reverse();
                return Some(path);
            }

            if let Some(neighbors) = self.vouches.get(&current) {
                for neighbor in neighbors {
                    if !visited.contains_key(neighbor) {
                        visited.insert(*neighbor, current);
                        queue.push_back((*neighbor, hops + 1));
                    }
                }
            }
        }

        None
    }
}

impl Default for TrustGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(byte: u8) -> NodeId {
        NodeId([byte; 32])
    }

    #[test]
    fn test_vouch_create_verify() {
        let voucher = Identity::generate();
        let vouchee = Identity::generate();
        let vouch = Vouch::create(
            &voucher,
            vouchee.node_id(),
            &vouchee.public_key_bytes(),
            "Bob",
            1000,
        );
        assert!(vouch.verify());
    }

    #[test]
    fn test_vouch_tampered() {
        let voucher = Identity::generate();
        let vouchee = Identity::generate();
        let mut vouch = Vouch::create(
            &voucher,
            vouchee.node_id(),
            &vouchee.public_key_bytes(),
            "Bob",
            1000,
        );
        vouch.display_name = "Eve".to_string(); // tamper
        assert!(!vouch.verify());
    }

    #[test]
    fn test_trust_self() {
        let graph = TrustGraph::new();
        let a = make_node(1);
        let score = graph.trust_score(&a, &a);
        assert_eq!(score.value, 1.0);
        assert_eq!(score.hops, 0);
    }

    #[test]
    fn test_trust_direct() {
        let mut graph = TrustGraph::new();
        let a = make_node(1);
        let b = make_node(2);
        graph.add_vouch(a, b);

        let score = graph.trust_score(&a, &b);
        assert_eq!(score.value, 1.0);
        assert_eq!(score.hops, 1);
    }

    #[test]
    fn test_trust_two_hops() {
        let mut graph = TrustGraph::new();
        let a = make_node(1);
        let b = make_node(2);
        let c = make_node(3);
        graph.add_vouch(a, b);
        graph.add_vouch(b, c);

        let score = graph.trust_score(&a, &c);
        assert_eq!(score.value, 0.5);
        assert_eq!(score.hops, 2);
    }

    #[test]
    fn test_trust_three_hops() {
        let mut graph = TrustGraph::new();
        let a = make_node(1);
        let b = make_node(2);
        let c = make_node(3);
        let d = make_node(4);
        graph.add_vouch(a, b);
        graph.add_vouch(b, c);
        graph.add_vouch(c, d);

        let score = graph.trust_score(&a, &d);
        assert_eq!(score.value, 0.25);
        assert_eq!(score.hops, 3);
    }

    #[test]
    fn test_trust_no_path() {
        let mut graph = TrustGraph::new();
        let a = make_node(1);
        let b = make_node(2);
        let c = make_node(3);
        graph.add_vouch(a, b);
        // No path from a to c

        let score = graph.trust_score(&a, &c);
        assert_eq!(score.value, 0.0);
    }

    #[test]
    fn test_trust_beyond_max_hops() {
        let mut graph = TrustGraph::with_max_hops(2);
        let a = make_node(1);
        let b = make_node(2);
        let c = make_node(3);
        let d = make_node(4);
        graph.add_vouch(a, b);
        graph.add_vouch(b, c);
        graph.add_vouch(c, d);

        // 3 hops but max is 2
        let score = graph.trust_score(&a, &d);
        assert_eq!(score.value, 0.0);
    }

    #[test]
    fn test_trust_path() {
        let mut graph = TrustGraph::new();
        let a = make_node(1);
        let b = make_node(2);
        let c = make_node(3);
        graph.add_vouch(a, b);
        graph.add_vouch(b, c);

        let path = graph.trust_path(&a, &c).unwrap();
        assert_eq!(path, vec![a, b, c]);
    }

    #[test]
    fn test_trust_shortest_path() {
        let mut graph = TrustGraph::new();
        let a = make_node(1);
        let b = make_node(2);
        let c = make_node(3);
        let d = make_node(4);
        // a->b->c->d (3 hops)
        graph.add_vouch(a, b);
        graph.add_vouch(b, c);
        graph.add_vouch(c, d);
        // a->d direct (1 hop)
        graph.add_vouch(a, d);

        let score = graph.trust_score(&a, &d);
        assert_eq!(score.value, 1.0);
        assert_eq!(score.hops, 1);
    }

    #[test]
    fn test_remove_vouch() {
        let mut graph = TrustGraph::new();
        let a = make_node(1);
        let b = make_node(2);
        graph.add_vouch(a, b);
        assert_eq!(graph.trust_score(&a, &b).hops, 1);

        graph.remove_vouch(&a, &b);
        assert_eq!(graph.trust_score(&a, &b).value, 0.0);
    }

    #[test]
    fn test_vouched_by_node() {
        let mut graph = TrustGraph::new();
        let a = make_node(1);
        let b = make_node(2);
        let c = make_node(3);
        graph.add_vouch(a, b);
        graph.add_vouch(a, c);

        let mut vouched = graph.vouched_by_node(&a);
        vouched.sort_by_key(|n| n.0);
        assert_eq!(vouched.len(), 2);
    }
}
