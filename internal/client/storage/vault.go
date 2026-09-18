package storage

import (
	"sort"
	"time"
)

type Record struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Payload   []byte    `json:"payload"`
	Metadata  []byte    `json:"metadata"`
	Version   int64     `json:"version"`
	Deleted   bool      `json:"deleted"`
	UpdatedAt time.Time `json:"updated_at"`
	Dirty     bool      `json:"dirty"`
}

type Vault struct {
	Cursor  time.Time         `json:"cursor"`
	Records map[string]Record `json:"records"`
}

func NewVault() *Vault {
	return &Vault{Records: make(map[string]Record)}
}

func (v *Vault) Get(id string) (Record, bool) {
	rec, ok := v.Records[id]
	return rec, ok
}

func (v *Vault) List() []Record {
	out := make([]Record, 0, len(v.Records))
	for _, rec := range v.Records {
		if rec.Deleted {
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].UpdatedAt.After(out[j].UpdatedAt)
	})
	return out
}

func (v *Vault) Put(id, secretType string, payload, metadata []byte, now time.Time) {
	rec, ok := v.Records[id]
	if !ok {
		rec = Record{ID: id, Type: secretType}
	}
	rec.Payload = payload
	rec.Metadata = metadata
	rec.Deleted = false
	rec.UpdatedAt = now
	rec.Dirty = true
	v.Records[id] = rec
}

func (v *Vault) MarkDeleted(id string, now time.Time) bool {
	rec, ok := v.Records[id]
	if !ok || rec.Deleted {
		return false
	}
	rec.Payload = nil
	rec.Metadata = nil
	rec.Deleted = true
	rec.UpdatedAt = now
	rec.Dirty = true
	v.Records[id] = rec
	return true
}

func (v *Vault) DirtyRecords() []Record {
	out := make([]Record, 0)
	for _, rec := range v.Records {
		if rec.Dirty {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].UpdatedAt.Before(out[j].UpdatedAt)
	})
	return out
}

func (v *Vault) ApplyServer(rec Record) {
	if rec.Deleted {
		delete(v.Records, rec.ID)
		return
	}
	rec.Dirty = false
	v.Records[rec.ID] = rec
}

func (v *Vault) MarkSynced(id string, version int64) {
	rec, ok := v.Records[id]
	if !ok {
		return
	}
	if rec.Deleted {
		delete(v.Records, id)
		return
	}
	rec.Version = version
	rec.Dirty = false
	v.Records[id] = rec
}
