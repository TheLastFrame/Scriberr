package service

import (
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

type FileService interface {
	SaveUpload(file *multipart.FileHeader, destDir string) (string, error)
	CreateDirectory(path string) error
	RemoveFile(path string) error
	RemoveDirectory(path string) error
	ReadFile(path string) ([]byte, error)
	FileExists(path string) (bool, error)
	SyncFileToRemote(localPath string) error
	SyncDirectoryToRemote(localDir string) error
}

type fileService struct {
	enabledS3  bool
	s3Bucket   string
	s3Prefix   string
	s3Endpoint string
}

func NewFileService() FileService {
	return &fileService{
		enabledS3:  strings.ToLower(os.Getenv("STORAGE_BACKEND")) == "s3" && os.Getenv("S3_BUCKET") != "",
		s3Bucket:   os.Getenv("S3_BUCKET"),
		s3Prefix:   strings.Trim(strings.TrimSpace(os.Getenv("S3_PREFIX")), "/"),
		s3Endpoint: strings.TrimSpace(os.Getenv("S3_ENDPOINT")),
	}
}

func (s *fileService) SaveUpload(fileHeader *multipart.FileHeader, destDir string) (string, error) {
	if err := s.CreateDirectory(destDir); err != nil {
		return "", err
	}
	id := uuid.New().String()
	ext := filepath.Ext(fileHeader.Filename)
	filePath := filepath.Join(destDir, fmt.Sprintf("%s%s", id, ext))
	src, err := fileHeader.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer src.Close()
	dst, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dst.Close()
	if _, err = io.Copy(dst, src); err != nil {
		_ = os.Remove(filePath)
		return "", fmt.Errorf("failed to copy file content: %w", err)
	}
	if err := s.SyncFileToRemote(filePath); err != nil {
		return "", err
	}
	return filePath, nil
}

func (s *fileService) SyncFileToRemote(localPath string) error {
	if !s.enabledS3 {
		return nil
	}
	relPath := filepath.ToSlash(strings.TrimPrefix(localPath, "./"))
	key := relPath
	if s.s3Prefix != "" {
		key = s.s3Prefix + "/" + relPath
	}
	dest := fmt.Sprintf("s3://%s/%s", s.s3Bucket, key)
	args := []string{"s3", "cp", localPath, dest}
	if s.s3Endpoint != "" {
		args = append(args, "--endpoint-url", s.s3Endpoint)
	}
	if out, err := exec.Command("aws", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to upload to s3 (%s): %w: %s", dest, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *fileService) SyncDirectoryToRemote(localDir string) error {
	if !s.enabledS3 {
		return nil
	}
	return filepath.Walk(localDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		return s.SyncFileToRemote(path)
	})
}
func (s *fileService) CreateDirectory(path string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}
	return nil
}
func (s *fileService) RemoveFile(path string) error         { return os.Remove(path) }
func (s *fileService) RemoveDirectory(path string) error    { return os.RemoveAll(path) }
func (s *fileService) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (s *fileService) FileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
