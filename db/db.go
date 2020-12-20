package db

import (
	"encoding/json"
	"errors"
	"fmt"

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
	opts := badger.DefaultOptions(dataDir)
	opts.NumVersionsToKeep = 0
	db, err := badger.Open(opts)
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

// SetMany ..
func (db *DB) SetMany(prefix string, keys []string, values []interface{}) error {
	wb := db.b.NewWriteBatch()
	defer wb.Cancel()
	for i, key := range keys {
		encoded, err := json.Marshal(values[i])
		if err != nil {
			return err
		}
		err = wb.Set([]byte(prefix+key), encoded) // Will create txns as needed.
		if err != nil {
			return err
		}
	}
	return wb.Flush() // Wait for all txns to finish.
}

// RefMany ..
func (db *DB) RefMany(prefix string, keys []string) error {
	nothing := make([]byte, 0)
	wb := db.b.NewWriteBatch()
	defer wb.Cancel()
	for _, key := range keys {
		err := wb.Set([]byte(prefix+key), nothing) // Will create txns as needed.
		if err != nil {
			return err
		}
	}
	return wb.Flush() // Wait for all txns to finish.
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
		maxOffset := int64(10000)
		if offset > maxOffset {
			return errors.New("offset too large (max value is 10000)")
		}
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

// Enumerate ..
func (db *DB) Enumerate(prefix string, enumProcessor func(key string, value []byte) (bool, error)) error {
	return db.b.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		prefixBytes := []byte(prefix)
		opts.Prefix = prefixBytes
		iter := txn.NewIterator(opts)
		defer iter.Close()
		for iter.Seek(opts.Prefix); iter.Valid(); iter.Next() {
			var cont bool
			iter.Item().Value(func(val []byte) error {
				var err error
				cont, err = enumProcessor(string(iter.Item().Key()), val)
				if err != nil {
					return err
				}
				return nil
			})
			if !cont {
				return nil
			}
		}
		return nil
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
