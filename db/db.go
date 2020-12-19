package db

import (
	"encoding/json"
	"fmt"

	badger "github.com/dgraph-io/badger/v2"
)

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

// Get ..
func (db *DB) Get(key string, valueProcessor func(value []byte) error) error {
	return db.b.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		item.Value(valueProcessor)
		return nil
	})
}

// Set ..
func (db *DB) Set(key string, value interface{}) error {
	return db.b.Update(func(txn *badger.Txn) error {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		err = txn.Set([]byte(key), encoded)
		if err != nil {
			return err
		}
		return nil
	})
}

// SetBulk ..
func (db *DB) SetBulk(keys []string, value interface{}) error {
	return db.b.Update(func(txn *badger.Txn) error {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		for _, key := range keys {
			err = txn.Set([]byte(key), encoded)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// List ..
func (db *DB) List(prefix string, offset int64, limit int64, valuesProcessor func(keys []string, values [][]byte) error) error {
	return db.b.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte(prefix)
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
				iter.Item().Value(func(val []byte) error {
					var key string
					err := json.Unmarshal(val, &key)
					if err != nil {
						return err
					}
					foundKeys = append(foundKeys, key)
					return nil
				})
			}
			pos++
			if pos-offset >= limit {
				break
			}
		}
		foundValues := make([][]byte, 0, limit)
		for _, foundKey := range foundKeys {
			item, err := txn.Get([]byte(foundKey))
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
