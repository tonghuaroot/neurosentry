// Copyright 2025 NeuroSentry Contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
)

type FileStore struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

func NewFileStore(path string) (*FileStore, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &FileStore{
		file: f,
		enc:  json.NewEncoder(f),
	}, nil
}

func (s *FileStore) Write(e *Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enc.Encode(e); err != nil {
		return err
	}
	return s.file.Sync()
}

func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

func LoadFromFile(path string) (*Chain, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	chain := &Chain{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			log.Printf("audit: skipping corrupt entry at line %d: %v", lineNum, err)
			continue
		}
		chain.entries = append(chain.entries, &e)
		if e.SequenceNum >= chain.nextSeq {
			chain.nextSeq = e.SequenceNum + 1
		}
	}
	chain.totalCount = int64(len(chain.entries))

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan audit log: %w", err)
	}

	return chain, nil
}
