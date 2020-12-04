package MerkleTree

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/spaolacci/murmur3"
	"github.com/willf/bitset"
)

// A BloomFilter is a representation of a set of _n_ items, where the main
// requirement is to make membership queries; _i.e._, whether an item is a
// member of a set.
type BloomFilter struct {
	m uint
	k uint
	b *bitset.BitSet
}

func max(x, y uint) uint {
	if x > y {
		return x
	}
	return y
}

// New creates a new Bloom filter with _m_ bits and _k_ hashing functions
// We force _m_ and _k_ to be at least one to avoid panics.
func New(m uint, k uint) *BloomFilter {
	return &BloomFilter{max(1, m), max(1, k), bitset.New(m)}
}

// From creates a new Bloom filter with len(_data_) * 64 bits and _k_ hashing
// functions. The data slice is not going to be reset.
func From(data []uint64, k uint) *BloomFilter {
	m := uint(len(data) * 64)
	return &BloomFilter{m, k, bitset.From(data)}
}

// baseHashes returns the four hash values of data that are used to create k
// hashes
func baseHashes(data []byte) [4]uint64 {
	a1 := []byte{1} // to grab another bit of data
	hasher := murmur3.New128()
	hasher.Write(data) // #nosec
	v1, v2 := hasher.Sum128()
	hasher.Write(a1) // #nosec
	v3, v4 := hasher.Sum128()
	return [4]uint64{
		v1, v2, v3, v4,
	}
}

// location returns the ith hashed location using the four base hash values
func location(h [4]uint64, i uint) uint64 {
	ii := uint64(i)
	return h[ii%2] + ii*h[2+(((ii+(ii%2))%4)/2)]
}

// location returns the ith hashed location using the four base hash values
func (f *BloomFilter) location(h [4]uint64, i uint) uint {
	return uint(location(h, i) % uint64(f.m))
}

// EstimateParameters estimates requirements for m and k.
func EstimateParameters(n uint, p float64) (m uint, k uint) {
	m = uint(math.Ceil(-1 * float64(n) * math.Log(p) / math.Pow(math.Log(2), 2)))
	k = uint(math.Ceil(math.Log(2) * float64(m) / float64(n)))
	return
}

// NewWithEstimates creates a new Bloom filter for about n items with fp
// false positive rate
func NewWithEstimates(n uint, fp float64) *BloomFilter {
	m, k := EstimateParameters(n, fp)
	return New(m, k)
}

// Cap returns the capacity, _m_, of a Bloom filter
func (f *BloomFilter) Cap() uint {
	return f.m
}

// K returns the number of hash functions used in the BloomFilter
func (f *BloomFilter) K() uint {
	return f.k
}

// Add data to the Bloom Filter. Returns the filter (allows chaining)
func (f *BloomFilter) Add(data []byte) *BloomFilter {
	h := baseHashes(data)
	for i := uint(0); i < f.k; i++ {
		f.b.Set(f.location(h, i))
	}
	return f
}

// Merge the data from two Bloom Filters.
func (f *BloomFilter) Merge(g *BloomFilter) error {
	// Make sure the m's and k's are the same, otherwise merging has no real use.
	if f.m != g.m {
		return fmt.Errorf("m's don't match: %d != %d", f.m, g.m)
	}

	if f.k != g.k {
		return fmt.Errorf("k's don't match: %d != %d", f.m, g.m)
	}

	f.b.InPlaceUnion(g.b)
	return nil
}

// Copy creates a copy of a Bloom filter.
func (f *BloomFilter) Copy() *BloomFilter {
	fc := New(f.m, f.k)
	fc.Merge(f) // #nosec
	return fc
}

// AddString to the Bloom Filter. Returns the filter (allows chaining)
func (f *BloomFilter) AddString(data string) *BloomFilter {
	return f.Add([]byte(data))
}

// Test returns true if the data is in the BloomFilter, false otherwise.
// If true, the result might be a false positive. If false, the data
// is definitely not in the set.
func (f *BloomFilter) Test(data []byte) bool {
	h := baseHashes(data)
	for i := uint(0); i < f.k; i++ {
		if !f.b.Test(f.location(h, i)) {
			return false
		}
	}
	return true
}

// TestString returns true if the string is in the BloomFilter, false otherwise.
// If true, the result might be a false positive. If false, the data
// is definitely not in the set.
func (f *BloomFilter) TestString(data string) bool {
	return f.Test([]byte(data))
}

// TestLocations returns true if all locations are set in the BloomFilter, false
// otherwise.
func (f *BloomFilter) TestLocations(locs []uint64) bool {
	for i := 0; i < len(locs); i++ {
		if !f.b.Test(uint(locs[i] % uint64(f.m))) {
			return false
		}
	}
	return true
}

// TestAndAdd is the equivalent to calling Test(data) then Add(data).
// Returns the result of Test.
func (f *BloomFilter) TestAndAdd(data []byte) bool {
	present := true
	h := baseHashes(data)
	for i := uint(0); i < f.k; i++ {
		l := f.location(h, i)
		if !f.b.Test(l) {
			present = false
		}
		f.b.Set(l)
	}
	return present
}

// TestAndAddString is the equivalent to calling Test(string) then Add(string).
// Returns the result of Test.
func (f *BloomFilter) TestAndAddString(data string) bool {
	return f.TestAndAdd([]byte(data))
}

// ClearAll clears all the data in a Bloom filter, removing all keys
func (f *BloomFilter) ClearAll() *BloomFilter {
	f.b.ClearAll()
	return f
}

// EstimateFalsePositiveRate returns, for a BloomFilter with a estimate of m bits
// and k hash functions, what the false positive rate will be
// while storing n entries; runs 100,000 tests. This is an empirical
// test using integers as keys. As a side-effect, it clears the BloomFilter.
func (f *BloomFilter) EstimateFalsePositiveRate(n uint) (fpRate float64) {
	rounds := uint32(100000)
	f.ClearAll()
	n1 := make([]byte, 4)
	for i := uint32(0); i < uint32(n); i++ {
		binary.BigEndian.PutUint32(n1, i)
		f.Add(n1)
	}
	fp := 0
	// test for number of rounds
	for i := uint32(0); i < rounds; i++ {
		binary.BigEndian.PutUint32(n1, i+uint32(n)+1)
		if f.Test(n1) {
			//fmt.Printf("%v failed.\n", i+uint32(n)+1)
			fp++
		}
	}
	fpRate = float64(fp) / (float64(rounds))
	f.ClearAll()
	return
}

// Equal tests for the equality of two Bloom filters
func (f *BloomFilter) Equal(g *BloomFilter) bool {
	return f.m == g.m && f.k == g.k && f.b.Equal(g.b)
}

// Locations returns a list of hash locations representing a data item.
func Locations(data []byte, k uint) []uint64 {
	locs := make([]uint64, k)

	// calculate locations
	h := baseHashes(data)
	for i := uint(0); i < k; i++ {
		locs[i] = location(h, i)
	}

	return locs
}
