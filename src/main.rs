use hex;
use tiny_keccak::Hasher;
use tiny_keccak::Sha3;

#[derive(Clone)]
struct MerkleNode {
    left: Option<Box<MerkleNode>>,
    right: Option<Box<MerkleNode>>,
    hash: String,
}

impl MerkleNode {
    fn new(data: &str) -> Self {
        let hash = hash(data);
        MerkleNode {
            left: None,
            right: None,
            hash,
        }
    }

    fn combine(left: MerkleNode, right: MerkleNode) -> Self {
        let mut hasher = Sha3::v256();
        let mut combined_hash = [0u8; 32];

        hasher.update(left.hash.as_bytes());
        hasher.update(right.hash.as_bytes());
        hasher.finalize(&mut combined_hash);

        let hash = hex::encode(combined_hash);
        MerkleNode {
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
            hash,
        }
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

    pub fn generate_proof(&self, data: &str) -> Vec<String> {
        let mut proof: Vec<String> = Vec::new();
        let leaf = MerkleNode::new(data);

        self.traverse_tree(&self.root, &leaf, &mut proof);

        proof
    }

    fn traverse_tree(&self, current: &MerkleNode, leaf: &MerkleNode, proof: &mut Vec<String>) {
        if current.hash == leaf.hash {
            return;
        }
    
        if let Some(left) = &current.left {
            if left.hash != leaf.hash {
                proof.push(left.hash.clone());
                self.traverse_tree(left, leaf, proof);
            } else {
                self.traverse_tree(left, left, proof);
            }
        }
    
        if let Some(right) = &current.right {
            if right.hash != leaf.hash {
                proof.push(right.hash.clone());
                self.traverse_tree(right, leaf, proof);
            } else {
                self.traverse_tree(right, right, proof);
            }
        }
    }

    pub fn verify_proof(&self, data: &str, proof: &[String]) -> bool {
        let leaf = MerkleNode::new(data);
        let mut current_hash = leaf.hash.clone();

        for sibling_hash in proof.iter() {
            let mut hasher = Sha3::v256();
            let mut combined_hash = [0u8; 32];
            let mut hash_input = [0u8; 64];

            hex::decode_to_slice(current_hash.as_str(), &mut hash_input[0..32])
                .expect("Invalid hash");
            hex::decode_to_slice(sibling_hash, &mut hash_input[32..64]).expect("Invalid hash");

            hasher.update(&hash_input);
            hasher.finalize(&mut combined_hash);

            current_hash = hex::encode(combined_hash);
        }

        current_hash == leaf.hash
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
    let data = vec!["rust2"];
    let merkle_tree = MerkleTree::new(data.clone());

    println!("Root Hash (Keccak-256): {}", merkle_tree.root_hash());

    let data_to_verify = "rust2";
    let proof = merkle_tree.generate_proof(data_to_verify.clone());
    let is_verified = merkle_tree.verify_proof(data_to_verify, &proof);

    if is_verified {
        println!("Data integrity verified for '{}'", data_to_verify);
    } else {
        println!(
            "Data integrity verification failed for '{}'",
            data_to_verify
        );
    }
}
