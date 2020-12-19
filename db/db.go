package db

import (
	"encoding/json"
	"errors"
	"fmt"

	badger "github.com/dgraph-io/badger/v2"
)

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

// Get ..
func (db *DB) Get(key string, valueProcessor func(value []byte) error) error {
	return db.b.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
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

// SetManyRefs ..
func (db *DB) SetManyRefs(keys []string, ref string) error {
	return db.b.Update(func(txn *badger.Txn) error {
		for _, key := range keys {
			err := txn.Set([]byte(key), []byte(ref))
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// Del ..
func (db *DB) Del(key string) error {
	return db.b.Update(func(txn *badger.Txn) error {
		err := txn.Delete([]byte(key))
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
func (db *DB) DelManyRefs(keys []string) error {
	return db.b.Update(func(txn *badger.Txn) error {
		for _, key := range keys {
			err := txn.Delete([]byte(key))
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
func (db *DB) List(prefix string, offset int64, limit int64, valuesProcessor func(keys [][]byte, values [][]byte) error) error {
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
		foundKeys := make([][]byte, 0, limit)
		for iter.Seek(opts.Prefix); iter.Valid(); iter.Next() {
			if pos >= offset && pos-offset < limit {
				iter.Item().Value(func(val []byte) error {
					foundKeys = append(foundKeys, val)
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
			item, err := txn.Get(foundKey)
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
