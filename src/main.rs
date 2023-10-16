
use tiny_keccak::Hasher;
use tiny_keccak::Sha3;
#[derive(Clone, Debug)]
pub struct MerkleNode {
    left: Option<Box<MerkleNode>>,
    right: Option<Box<MerkleNode>>,
    hash: Vec<u8>,
}

impl MerkleNode {
    fn new(hash: Vec<u8>) -> Self {
        MerkleNode {
            left: None,
            right: None,
            hash,
        }
    }
}

pub struct MerkleTree {
    root: Option<Box<MerkleNode>>,
}

impl MerkleTree {
    pub fn from_data_blocks(data_blocks: &[&[u8]]) -> Self {
        let num_blocks = data_blocks.len();
        let mut leaf_nodes = Vec::with_capacity(num_blocks);

        for block in data_blocks {
            let hash = Self::hash(block);
            leaf_nodes.push(Box::new(MerkleNode::new(hash)));
        }

        MerkleTree::build_tree(leaf_nodes)
    }

    pub fn from_leaf_hashes(leaf_hashes: &[Vec<u8>]) -> Self {
        let num_leaves = leaf_hashes.len();
        let mut leaf_nodes = Vec::with_capacity(num_leaves);

        for hash in leaf_hashes.iter() {
            leaf_nodes.push(Box::new(MerkleNode::new(hash.clone())));
        }

        MerkleTree::build_tree(leaf_nodes)
    }

    fn build_tree(mut nodes: Vec<Box<MerkleNode>>) -> Self {
        assert!(!nodes.is_empty(), "Cannot build a tree with no nodes");

        while nodes.len() > 1 {
            let mut parents = Vec::new();

            for chunk in nodes.chunks(2) {
                let left = chunk[0].clone();
                let right = if chunk.len() > 1 {
                    chunk[1].clone()
                } else {
                    left.clone() 
                };
                let combined_hash = Self::combine_hashes(&left.hash, &right.hash);
                let mut parent = Box::new(MerkleNode::new(combined_hash));
                parent.left = Some(left);
                parent.right = Some(right);
                parents.push(parent);
            }

            nodes = parents;
        }

        MerkleTree {
            root: Some(nodes.remove(0)),
        }
    }

    pub fn root_hex(&self) -> String {
        match &self.root {
            Some(root_node) => hex::encode(&root_node.hash),
            None => "".to_string(),
        }
    }

    pub fn verify_integrity(&self, data: &[u8]) -> bool {
        match &self.root {
            Some(root_node) => {
                let root_hash = &root_node.hash;
                let data_hash = Self::hash(data);
                root_hash == &data_hash
            }
            None => false,
        }
    }

    /// Generates a cryptographic proof for the provided data
    pub fn generate_proof(&self, data: &[u8]) -> Option<Vec<Vec<u8>>> {
        match &self.root {
            Some(root_node) => {
                let target_hash = Self::hash(data);
                let mut proof = Vec::new();

                Self::search_node(&target_hash, root_node, &mut proof);
                if proof.is_empty() {
                    None
                } else {
                    Some(proof)
                }
            }
            None => None,
        }
    }

    fn search_node(target_hash: &[u8], node: &MerkleNode, proof: &mut Vec<Vec<u8>>) {
        if node.hash == *target_hash {
            return;
        }
    
        if let Some(left) = &node.left {
            if &left.hash == target_hash {
                proof.push(node.right.as_ref().unwrap().hash.clone());
                Self::search_node(target_hash, &*left, proof);
            } else {
                Self::search_node(target_hash, &*left, proof);
                if let Some(right) = &node.right {
                    proof.push(right.hash.clone());
                }
            }
        }
    }

    fn hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3::v256();
        hasher.update(data);
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        output.to_vec()
    }

    fn combine_hashes(left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut combined_data = Vec::new();
        combined_data.extend_from_slice(left);
        combined_data.extend_from_slice(right);
        Self::hash(&combined_data)
    }
}

fn main() {
    let data = vec![0, 1, 2, 3, 4, 5];
    
    let merkle_tree = MerkleTree::from_data_blocks(&[&data]);

    println!("Root Hash (Keccack-256): {}", merkle_tree.root_hex());

    let is_integrity_verified = merkle_tree.verify_integrity(&data);
    println!("Data integrity verified: {}", is_integrity_verified);

    let proof = merkle_tree.generate_proof(&data);
    if let Some(proof) = proof {
        println!("Cryptographic Proof:");
        for (index, hash) in proof.iter().enumerate() {
            println!("Proof {}: {}", index + 1, hex::encode(&hash));
        }
    } else {
        println!("Failed to generate a cryptographic proof.");
    }
}
