use hex;
use tiny_keccak::Hasher;
use tiny_keccak::Sha3;

#[derive(Clone)]
struct MerkleNode {
    hash: String,
}

impl MerkleNode {
    fn new(data: &str) -> Self {
        let hash = hash(data);
        MerkleNode { hash }
    }

    fn combine(left: MerkleNode, right: MerkleNode) -> Self {
        let mut hasher = Sha3::v256();
        let mut combined_hash = [0u8; 32];

        hasher.update(left.hash.as_bytes());
        hasher.update(right.hash.as_bytes());
        hasher.finalize(&mut combined_hash);

        let hash = hex::encode(combined_hash);
        MerkleNode { hash }
    }
}

pub struct MerkleTree {
    root: MerkleNode,
}

impl MerkleTree {
    pub fn new(data: Vec<&str>) -> Self {
        let leaves: Vec<MerkleNode> = data.iter().map(|d| MerkleNode::new(d)).collect();
        let root = MerkleTree::build_tree(leaves);
        MerkleTree { root }
    }

    fn build_tree(mut nodes: Vec<MerkleNode>) -> MerkleNode {
        if nodes.len() == 1 {
            return nodes.remove(0);
        }
        let mut new_nodes = vec![];
        for i in (0..nodes.len()).step_by(2) {
            let left = nodes[i].clone();
            let right = if i + 1 < nodes.len() {
                nodes[i + 1].clone()
            } else {
                left.clone()
            };
            let combined = MerkleNode::combine(left, right);
            new_nodes.push(combined);
        }
        MerkleTree::build_tree(new_nodes)
    }

    pub fn root_hash(&self) -> &str {
        &self.root.hash
    }
}

fn hash(data: &str) -> String {
    let mut hasher = Sha3::v256();
    let mut output = [0u8; 32];
    hasher.update(data.as_bytes());
    hasher.finalize(&mut output);
    hex::encode(output)
}

fn main() {
    let data = vec!["rust1", "rust2", "rust3", "rust4"];
    let merkle_tree = MerkleTree::new(data);

    println!("Root Hash (Keccak-256): {}", merkle_tree.root_hash());
}
