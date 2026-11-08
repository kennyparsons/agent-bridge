package daemonlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/acl"
)

const (
	// DefaultMaxBytes is the default maximum log file size before rotation (10 MiB).
	DefaultMaxBytes int64 = 10 << 20
	// DefaultMaxBackups is the default number of rotated backup files retained (daemon.log.1 .. daemon.log.5).
	DefaultMaxBackups int = 5
	// DefaultPollInterval is the polling cadence used by Follow for cross-OS tailing.
	DefaultPollInterval = 250 * time.Millisecond

	tailChunkSize int64 = 32 * 1024
)

// Options configures a RotatingWriter.
type Options struct {
	Path       string
	MaxBytes   int64
	MaxBackups int
}

// RotatingWriter is a concurrency-safe, size-rotating io.WriteCloser that opens active log files
// with shared read/write/delete semantics on Windows so concurrent readers never hit sharing violations.
type RotatingWriter struct {
	mu         sync.Mutex
	path       string
	maxBytes   int64
	maxBackups int
	file       *os.File
	size       int64
	closed     bool
}

// Open opens or creates a RotatingWriter at path with DefaultMaxBytes (10 MiB) and DefaultMaxBackups (5).
func Open(path string) (*RotatingWriter, error) {
	return NewRotatingWriter(Options{Path: path})
}

// NewRotatingWriter creates a RotatingWriter with the provided Options, locking down the parent
// directory and active log file via internal/acl.
func NewRotatingWriter(opts Options) (*RotatingWriter, error) {
	trimmed := strings.TrimSpace(opts.Path)
	if trimmed == "" {
		return nil, errors.New("daemonlog: log path cannot be empty")
	}
	cleanPath := filepath.Clean(trimmed)

	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	maxBackups := opts.MaxBackups
	if maxBackups <= 0 {
		maxBackups = DefaultMaxBackups
	}

	w := &RotatingWriter{
		path:       cleanPath,
		maxBytes:   maxBytes,
		maxBackups: maxBackups,
	}
	if err := w.openOrCreateLocked(); err != nil {
		return nil, err
	}
	return w, nil
}

// Path returns the active log file path.
func (w *RotatingWriter) Path() string {
	return w.path
}

// Write appends p to the active log file, rotating backups first if the write would exceed MaxBytes.
func (w *RotatingWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return 0, os.ErrClosed
	}
	if w.file == nil {
		if err := w.openOrCreateLocked(); err != nil {
			return 0, err
		}
	}

	if w.size > 0 && w.size+int64(len(p)) > w.maxBytes {
		if err := w.rotateLocked(); err != nil {
			return 0, err
		}
	}

	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// Rotate forces an immediate log rotation (daemon.log -> daemon.log.1 .. daemon.log.<MaxBackups>).
func (w *RotatingWriter) Rotate() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return os.ErrClosed
	}
	return w.rotateLocked()
}

// Sync flushes buffered filesystem data for the active log file.
func (w *RotatingWriter) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return os.ErrClosed
	}
	if w.file == nil {
		return nil
	}
	return w.file.Sync()
}

// Close flushes and closes the active log file handle. Subsequent Close calls are no-ops.
func (w *RotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.file == nil {
		return nil
	}
	_ = w.file.Sync()
	err := w.file.Close()
	w.file = nil
	return err
}

func (w *RotatingWriter) openOrCreateLocked() error {
	dir := filepath.Dir(w.path)
	if err := acl.LockdownServerDir(dir); err != nil {
		return fmt.Errorf("daemonlog: failed to prepare log directory %q: %w", dir, err)
	}

	f, err := openAppendShared(w.path)
	if err != nil {
		return fmt.Errorf("daemonlog: failed to open log file %q: %w", w.path, err)
	}

	if lockErr := acl.LockdownPrivateFile(w.path); lockErr != nil {
		_ = f.Close()
		return fmt.Errorf("daemonlog: failed to lock down log file %q: %w", w.path, lockErr)
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("daemonlog: failed to stat log file %q: %w", w.path, err)
	}

	w.file = f
	w.size = info.Size()
	return nil
}

func (w *RotatingWriter) rotateLocked() error {
	if w.file != nil {
		_ = w.file.Sync()
		if err := w.file.Close(); err != nil {
			return fmt.Errorf("daemonlog: failed closing active log before rotation: %w", err)
		}
		w.file = nil
		w.size = 0
	}

	oldest := backupPath(w.path, w.maxBackups)
	if err := os.Remove(oldest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("daemonlog: failed removing oldest backup %q: %w", oldest, err)
	}

	for i := w.maxBackups - 1; i >= 1; i-- {
		src := backupPath(w.path, i)
		dst := backupPath(w.path, i+1)
		if _, err := os.Stat(src); err == nil {
			if renErr := os.Rename(src, dst); renErr != nil && !errors.Is(renErr, os.ErrNotExist) {
				return fmt.Errorf("daemonlog: failed rotating %q -> %q: %w", src, dst, renErr)
			}
		}
	}

	if _, err := os.Stat(w.path); err == nil {
		firstBackup := backupPath(w.path, 1)
		if err := os.Rename(w.path, firstBackup); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("daemonlog: failed rotating %q -> %q: %w", w.path, firstBackup, err)
		}
	}

	return w.openOrCreateLocked()
}

func backupPath(base string, index int) string {
	return fmt.Sprintf("%s.%d", base, index)
}

// TailLines returns up to the last `lines` lines from path (without trailing CR/LF characters),
// reading backward from EOF in fixed-size chunks with shared-read semantics.
func TailLines(path string, lines int) ([]string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, errors.New("daemonlog: log path cannot be empty")
	}
	cleanPath := filepath.Clean(trimmed)

	f, err := openReadShared(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("daemonlog: failed to open %q: %w", cleanPath, err)
	}
	defer func() {
		_ = f.Close()
	}()

	if lines <= 0 {
		return []string{}, nil
	}

	endOffset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("daemonlog: failed seeking %q: %w", cleanPath, err)
	}
	result, err := readLastLinesUpToOffset(f, endOffset, lines)
	if err != nil {
		return nil, fmt.Errorf("daemonlog: failed reading tail of %q: %w", cleanPath, err)
	}
	return result, nil
}

// Follow writes the last `initialLines` of `path` (when > 0) to `out` and then polls `path` every
// 250ms until `ctx.Done()`, streaming newly appended log output and seamlessly reopening `path`
// across size-based log rotations or truncations.
func Follow(ctx context.Context, path string, initialLines int, out io.Writer) error {
	return followWithInterval(ctx, path, initialLines, out, DefaultPollInterval)
}

func followWithInterval(
	ctx context.Context,
	path string,
	initialLines int,
	out io.Writer,
	pollInterval time.Duration,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if out == nil {
		return errors.New("daemonlog: output writer cannot be nil")
	}
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return errors.New("daemonlog: log path cannot be empty")
	}
	cleanPath := filepath.Clean(trimmed)
	if pollInterval <= 0 {
		pollInterval = DefaultPollInterval
	}

	f, err := openReadShared(cleanPath)
	if err != nil {
		return fmt.Errorf("daemonlog: failed to open %q: %w", cleanPath, err)
	}
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	curInfo, err := f.Stat()
	if err != nil {
		return fmt.Errorf("daemonlog: failed to stat %q: %w", cleanPath, err)
	}

	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("daemonlog: failed seeking %q: %w", cleanPath, err)
	}

	if initialLines > 0 && offset > 0 {
		lines, tailErr := readLastLinesUpToOffset(f, offset, initialLines)
		if tailErr != nil {
			return fmt.Errorf("daemonlog: failed reading initial lines of %q: %w", cleanPath, tailErr)
		}
		for _, line := range lines {
			if _, wErr := io.WriteString(out, line+"\n"); wErr != nil {
				return wErr
			}
		}
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	buf := make([]byte, 32*1024)

	drainHandle := func(handle *os.File, startOffset int64) (int64, error) {
		if handle == nil {
			return startOffset, nil
		}
		if _, seekErr := handle.Seek(startOffset, io.SeekStart); seekErr != nil {
			return startOffset, nil
		}
		cur := startOffset
		for {
			n, rErr := handle.Read(buf)
			if n > 0 {
				cur += int64(n)
				if _, wErr := out.Write(buf[:n]); wErr != nil {
					return cur, wErr
				}
			}
			if rErr != nil {
				if errors.Is(rErr, io.EOF) {
					return cur, nil
				}
				return cur, nil
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if f != nil {
				newOffset, wErr := drainHandle(f, offset)
				offset = newOffset
				if wErr != nil {
					return wErr
				}
			}

			statInfo, statErr := os.Stat(cleanPath)
			if statErr != nil {
				if errors.Is(statErr, os.ErrNotExist) {
					// Transient mid-rotation rename gap; retry on next poll tick.
					continue
				}
				continue
			}

			rotatedOrTruncated := f == nil ||
				(curInfo != nil && !os.SameFile(curInfo, statInfo)) ||
				statInfo.Size() < offset

			if rotatedOrTruncated {
				if f != nil {
					// Drain any final bytes written to the rotated file before closing it.
					if _, wErr := drainHandle(f, offset); wErr != nil {
						return wErr
					}
					_ = f.Close()
					f = nil
				}

				reopened, openErr := openReadShared(cleanPath)
				if openErr != nil {
					continue
				}
				reopenedInfo, infoErr := reopened.Stat()
				if infoErr != nil {
					_ = reopened.Close()
					continue
				}
				f = reopened
				curInfo = reopenedInfo
				offset = 0

				newOffset, wErr := drainHandle(f, 0)
				offset = newOffset
				if wErr != nil {
					return wErr
				}
			}
		}
	}
}

func readLastLinesUpToOffset(f *os.File, endOffset int64, lines int) ([]string, error) {
	if endOffset <= 0 || lines <= 0 {
		return []string{}, nil
	}

	// Collect chunks from EOF backward until we observe at least `lines + 1` newlines (or reach offset 0).
	var chunks [][]byte
	newlineCount := 0
	pos := endOffset

	for pos > 0 && newlineCount <= lines {
		readSize := tailChunkSize
		if pos < readSize {
			readSize = pos
		}
		pos -= readSize

		chunk := make([]byte, readSize)
		n, err := f.ReadAt(chunk, pos)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		chunk = chunk[:n]
		newlineCount += bytes.Count(chunk, []byte{'\n'})
		chunks = append(chunks, chunk)
	}

	totalLen := 0
	for _, c := range chunks {
		totalLen += len(c)
	}
	combined := make([]byte, 0, totalLen)
	for i := len(chunks) - 1; i >= 0; i-- {
		combined = append(combined, chunks[i]...)
	}

	// Drop a single trailing newline so "a\nb\n" splits into ["a", "b"] rather than ["a", "b", ""].
	if len(combined) > 0 && combined[len(combined)-1] == '\n' {
		combined = combined[:len(combined)-1]
	}
	if len(combined) == 0 {
		return []string{}, nil
	}

	rawLines := bytes.Split(combined, []byte{'\n'})
	startIdx := 0
	if len(rawLines) > lines {
		startIdx = len(rawLines) - lines
	}

	out := make([]string, 0, len(rawLines)-startIdx)
	for _, raw := range rawLines[startIdx:] {
		out = append(out, string(bytes.TrimSuffix(raw, []byte{'\r'})))
	}
	return out, nil
}
