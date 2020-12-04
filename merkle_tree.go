package MerkleTree

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
)

// The object stored in the tree should implement `Content` interface.
type Content interface {
	Hash() ([]byte, error)
	Equals(o Content) (bool, error)
}

type Node struct {
	tree *MerkleTree
	parent *Node
	left *Node
	right *Node
	isLeaf bool
	isDup bool
	nodeHash []byte
	content Content

	bf *BloomFilter
}

// `MerkleTree` is a core structure of this library.
// `root`: a pointer to the root of MerkleTree
// `rootHash`: hash of root node
// `leaves`: a list of pointers to leaf nodes
type MerkleTree struct {
	root 		*Node
	rootHash    []byte
	leaves      []*Node

	hashPolicy  func() hash.Hash
	enableBF    bool
	bf_m        uint
	bf_k        uint
}

//String returns a string representation of the node.
func (node *Node) String() string {
	return fmt.Sprintf("%t %t %v %s", node.isLeaf, node.isDup, node.nodeHash, node.content)
}

//
func (node *Node) verifyNode() ([]byte, error) {
	if node.isLeaf {
		return node.content.Hash()
	}
	leftBytes, err := node.left.verifyNode()
	if err != nil {
		return nil, err
	}
	rightBytes, err := node.right.verifyNode()
	if err != nil {
		return nil, err
	}
	h := node.tree.hashPolicy()
	_, err = h.Write(append(leftBytes, rightBytes...))
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (node *Node) calculateHash() ([]byte, error) {
	if node.isLeaf {
		return node.content.Hash()
	}
	h := node.tree.hashPolicy()
	_, err := h.Write(append(node.left.nodeHash, node.right.nodeHash...))
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (node *Node) bloomCheck(content Content) (bool, *Node, error) {
	if !node.tree.enableBF {
		return false, nil, errors.New("bloom filter is disabled")
	}
	if node.isLeaf {
		ok, err := node.content.Equals(content)
		if err != nil {
			return false, nil, err
		}
		if !ok {
			return false, nil, nil
		}
		return true, node, nil
	}
	h, err := content.Hash()
	if err != nil {
		return false, nil, err
	}
	if !node.bf.Test(h) {
		return false, nil, nil
	}
	bLeft, nLeft, err := node.left.bloomCheck(content)
	if err != nil {
		return false, nil, err
	}
	bRight, nRight, err := node.right.bloomCheck(content)
	if err != nil {
		return false, nil, err
	}
	if !bLeft && !bRight {
		return false, nil, nil
	}
	if bLeft {
		return true, nLeft, nil
	}
	return true, nRight, nil
}


// Recursively build internal nodes in Merkle Tree.
func buildInternalNodes(leaves []*Node, tree *MerkleTree) (*Node, error) {
	nextLevelNodes := make([]*Node, 0)
	for i := 0; i < len(leaves); i += 2 {
		left, right := i, i + 1
		if i + 1 == len(leaves) {
			right = i
		}
		h := tree.hashPolicy()
		if _, err := h.Write(append(leaves[left].nodeHash, leaves[right].nodeHash...));
			err != nil {
				return nil, err
		}

		newNode := &Node {
			tree: tree,
			left: leaves[left],
			right: leaves[right],
			nodeHash: h.Sum(nil),
		}
		// Bloom Filter Optimization
		if tree.enableBF {
			bf := newNode.left.bf.Copy()
			bf.Merge(newNode.right.bf)
			newNode.bf = bf
		}
		nextLevelNodes = append(nextLevelNodes, newNode)
		leaves[left].parent = newNode
		leaves[right].parent = newNode
		if len(leaves) == 2 {
			return newNode, nil
		}
	}
	return buildInternalNodes(nextLevelNodes, tree)
}

// Generate a merkle tree with the given set of Contents,
// return the root node, a list of leaves
func buildTreeWithContents(contents []Content, tree *MerkleTree) (*Node, []*Node, error) {
	if len(contents) == 0 {
		return nil, nil, errors.New("no contents")
	}
	// store leaves first.
	leaves := make([]*Node, 0)
	for _, content := range contents {
		h, err := content.Hash()
		if err != nil {
			return nil, nil, err
		}
		n := &Node {
			tree: tree,
			isLeaf: true,
			nodeHash: h,
			content: content,
		}
		if tree.enableBF {
			bf := New(tree.bf_m, tree.bf_k)
			bf.Add(n.nodeHash)
			n.bf = bf
		}
		leaves = append(leaves, n)
	}
	// make a duplicated node if there are odd nodes
	if len(contents) % 2 == 1 {
		dupLeaf := &Node {
			tree: tree,
			isLeaf: true,
			isDup: true,
			nodeHash: leaves[len(leaves) - 1].nodeHash,
			content: leaves[len(leaves) - 1].content,
		}
		// Bloom Filter Optimization
		if tree.enableBF {
			bf := New(tree.bf_m, tree.bf_k)
			bf.Add(dupLeaf.nodeHash)
			dupLeaf.bf = bf
		}
		leaves = append(leaves, dupLeaf)
	}

	// build internal nodes now.
	root, err := buildInternalNodes(leaves, tree)
	if err != nil {
		return nil, nil, err
	}
	return root, leaves, nil
}

// constructors of Merkle Tree
func NewTreeWithHashPolicyAndBloomFilter(contents []Content, policy func() hash.Hash, fp float64) (*MerkleTree, error) {
	n := len(contents)
	m, k := EstimateParameters(uint(n), fp)
	tree := &MerkleTree{
		hashPolicy: policy,
		enableBF: true,
		bf_m: m,
		bf_k: k,
	}
	root, leaves, err := buildTreeWithContents(contents, tree)
	if err != nil {
		return nil, err
	}
	tree.root = root
	tree.leaves = leaves
	tree.rootHash = root.nodeHash
	return tree, nil
}

func NewTreeWithBloomFilter(contents []Content, fp float64) (*MerkleTree, error) {
	return NewTreeWithHashPolicyAndBloomFilter(contents, sha256.New, fp)
}

func NewTreeWithHashPolicy(contents []Content, policy func() hash.Hash) (*MerkleTree, error) {
	tree := &MerkleTree{
		hashPolicy: policy,
	}
	root, leaves, err := buildTreeWithContents(contents, tree)
	if err != nil {
		return nil, err
	}
	tree.root = root
	tree.leaves = leaves
	tree.rootHash = root.nodeHash
	return tree, nil
}

func NewTree(contents []Content) (*MerkleTree, error) {
	return NewTreeWithHashPolicy(contents, sha256.New)
}

// Merkle Tree API
func (tree *MerkleTree) MerkleRoot() []byte {
	return tree.rootHash
}

func (tree *MerkleTree) VerifyTree() (bool, error) {
	calculatedRootHash, err := tree.root.verifyNode()
	if err != nil {
		return false, err
	}
	if bytes.Compare(calculatedRootHash, tree.rootHash) == 0 {
		return true, nil
	}
	return false, nil
}

// TODO: use Bloom Filter
func (tree *MerkleTree) VerifyContent(content Content) (bool, error) {
	if tree.enableBF {
		ok, leaf, err := tree.root.bloomCheck(content)
		if err != nil {
			return false, err
		}
		if ok {
			curparent := leaf.parent
			for curparent != nil {
				leftBytes, err := curparent.left.calculateHash()
				if err != nil {
					return false, err
				}
				rightBytes, err := curparent.right.calculateHash()
				if err != nil {
					return false, err
				}
				h := tree.hashPolicy()
				_, err = h.Write(append(leftBytes, rightBytes...))
				if err != nil {
					return false, err
				}
				if bytes.Compare(h.Sum(nil), curparent.nodeHash) != 0 {
					return false, nil
				}
				curparent = curparent.parent
			}
			return true, nil
		}
		return false, nil
	} else {
		for _, leaf := range tree.leaves {
			ok, err := leaf.content.Equals(content)
			if err != nil {
				return false, err
			}

			if ok {
				curparent := leaf.parent
				for curparent != nil {
					leftBytes, err := curparent.left.calculateHash()
					if err != nil {
						return false, err
					}
					rightBytes, err := curparent.right.calculateHash()
					if err != nil {
						return false, err
					}
					h := tree.hashPolicy()
					_, err = h.Write(append(leftBytes, rightBytes...))
					if err != nil {
						return false, err
					}
					if bytes.Compare(h.Sum(nil), curparent.nodeHash) != 0 {
						return false, nil
					}
					curparent = curparent.parent
				}
				return true, nil
			}
		}
		return false, nil
	}
}

// For tests
func (tree *MerkleTree) RebuildTree() error {
	contents := make([]Content, 0)
	for _, leaf := range tree.leaves {
		contents = append(contents, leaf.content)
	}
	root, leaves, err := buildTreeWithContents(contents, tree)
	if err != nil {
		return err
	}
	tree.root = root
	tree.leaves = leaves
	tree.rootHash = root.nodeHash
	return nil
}

// TODO: use Bloom Filter
func (tree *MerkleTree) GetMerkleMultiProof(content Content) ([][]byte, []int64, error) {
	if tree.enableBF {
		ok, leaf, err := tree.root.bloomCheck(content)
		if err != nil {
			return nil, nil, err
		}
		if ok {
			curparent := leaf.parent
			merklePath := make([][]byte, 0)
			index := make([]int64, 0)
			for curparent != nil {
				if bytes.Equal(curparent.left.nodeHash, leaf.nodeHash) {
					merklePath = append(merklePath, curparent.right.nodeHash)
					index = append(index, 1) // right leaf
				} else {
					merklePath = append(merklePath, curparent.left.nodeHash)
					index = append(index, 0) // left leaf
				}
				leaf = curparent
				curparent = curparent.parent
			}
			return merklePath, index, nil
		}
		return nil, nil, nil
	} else {
		for _, leaf := range tree.leaves {
			ok, err := leaf.content.Equals(content)
			if err != nil {
				return nil, nil, err
			}
			if ok {
				curparent := leaf.parent
				merklePath := make([][]byte, 0)
				index := make([]int64, 0)
				for curparent != nil {
					if bytes.Equal(curparent.left.nodeHash, leaf.nodeHash) {
						merklePath = append(merklePath, curparent.right.nodeHash)
						index = append(index, 1) // right leaf
					} else {
						merklePath = append(merklePath, curparent.left.nodeHash)
						index = append(index, 0) // left leaf
					}
					leaf = curparent
					curparent = curparent.parent
				}
				return merklePath, index, nil
			}
		}
		return nil, nil, nil
	}
}

// String returns a string representation of the tree.
// Only leaf nodes are included in the output.
func (tree *MerkleTree) String() string {
	s := ""
	for _, leaf := range tree.leaves {
		s += fmt.Sprint(leaf)
		s += "\n"
	}
	return s
}