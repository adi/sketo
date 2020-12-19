package db

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	badger "github.com/dgraph-io/badger/v2"
)

// ErrKeyNotFound ..
var ErrKeyNotFound = errors.New("Key not found")

// DB holds the database
type DB struct {
	b *badger.DB
}

// NewDB creates or loads a database at folder dataDir
func NewDB(dataDir string) (*DB, error) {
	db, err := badger.Open(badger.DefaultOptions(dataDir))
	if err != nil {
		return nil, err
	}
	return &DB{
		b: db,
	}, nil
}

// DelEverything ..
func (db *DB) DelEverything() error {
	return db.b.DropAll()
}

// Get ..
func (db *DB) Get(prefix string, key string, valueProcessor func(value []byte) error) error {
	return db.b.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(prefix + key))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				return ErrKeyNotFound
			}
			return err
		}
		item.Value(valueProcessor)
		return nil
	})
}

// Set ..
func (db *DB) Set(prefix string, key string, value interface{}) error {
	return db.b.Update(func(txn *badger.Txn) error {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		err = txn.Set([]byte(prefix+key), encoded)
		if err != nil {
			return err
		}
		return nil
	})
}

// RefMany ..
func (db *DB) RefMany(prefix string, keys []string) error {
	nothing := make([]byte, 0)
	return db.b.Update(func(txn *badger.Txn) error {
		for _, key := range keys {
			err := txn.Set([]byte(prefix+key), nothing)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// Del ..
func (db *DB) Del(prefix string, key string) error {
	return db.b.Update(func(txn *badger.Txn) error {
		err := txn.Delete([]byte(prefix + key))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				return nil
			}
			return err
		}
		return nil
	})
}

// DelManyRefs ..
func (db *DB) DelManyRefs(prefix string, keys []string) error {
	return db.b.Update(func(txn *badger.Txn) error {
		for _, key := range keys {
			err := txn.Delete([]byte(prefix + key))
			if err != nil {
				if err == badger.ErrKeyNotFound {
					return nil
				}
				return err
			}
		}
		return nil
	})
}

// List ..
func (db *DB) List(prefix string, filter string, offset int64, limit int64, valuesProcessor func(keys []string, values [][]byte) error) error {
	return db.b.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		prefixBytes := []byte(prefix + filter)
		opts.Prefix = prefixBytes
		iter := txn.NewIterator(opts)
		defer iter.Close()
		maxLimit := int64(100)
		if limit == -1 || limit > maxLimit {
			limit = maxLimit
		}
		pos := int64(0)
		foundKeys := make([]string, 0, limit)
		for iter.Seek(opts.Prefix); iter.Valid(); iter.Next() {
			if pos >= offset && pos-offset < limit {
				key := iter.Item().Key()
				foundKeys = append(foundKeys, string(key[len(prefixBytes):]))
			}
			pos++
			if pos-offset >= limit {
				break
			}
		}
		spew.Dump(foundKeys)
		foundValues := make([][]byte, 0, limit)
		for _, foundKey := range foundKeys {
			prefixBytes := []byte(prefix + foundKey)
			item, err := txn.Get(prefixBytes)
			if err != nil {
				return fmt.Errorf("can get key '%s': %w", string(foundKey), err)
			}
			item.Value(func(val []byte) error {
				foundValues = append(foundValues, val)
				return nil
			})
		}
		return valuesProcessor(foundKeys, foundValues)
	})
}

// Test ..
func (db *DB) Test(prefix string, filter string, allowedProcessor func(allowed bool) error) error {
	return db.b.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		prefixBytes := []byte(prefix + filter)
		opts.Prefix = prefixBytes
		iter := txn.NewIterator(opts)
		defer iter.Close()
		for iter.Seek(opts.Prefix); iter.Valid(); iter.Next() {
			return allowedProcessor(true)
		}
		return allowedProcessor(false)
	})
}

// Count ..
func (db *DB) Count(prefix string, filter string, countProcessor func(cnt int64) error) error {
	return db.b.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		prefixBytes := []byte(prefix + filter)
		opts.Prefix = prefixBytes
		iter := txn.NewIterator(opts)
		defer iter.Close()
		cnt := int64(0)
		for iter.Seek(opts.Prefix); iter.Valid(); iter.Next() {
			cnt++
		}
		return countProcessor(cnt)
	})
}
