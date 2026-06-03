package repository

import (
	"context"
	"testing"

	"scriberr/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestJobRepository_ListByUser_ScopesResults(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&models.TranscriptionJob{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	u1 := uint(1)
	u2 := uint(2)
	jobs := []models.TranscriptionJob{
		{ID: "job-u1-a", AudioPath: "a.wav", Status: models.StatusUploaded, UserID: &u1},
		{ID: "job-u1-b", AudioPath: "b.wav", Status: models.StatusUploaded, UserID: &u1},
		{ID: "job-u2-a", AudioPath: "c.wav", Status: models.StatusUploaded, UserID: &u2},
	}
	for i := range jobs {
		if err := db.Create(&jobs[i]).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	repo := NewJobRepository(db)
	got, total, err := repo.ListByUser(context.Background(), u1, 0, 20)
	if err != nil {
		t.Fatalf("list by user: %v", err)
	}
	if total != 2 {
		t.Fatalf("expected total=2, got %d", total)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 jobs, got %d", len(got))
	}
	for _, j := range got {
		if j.UserID == nil || *j.UserID != u1 {
			t.Fatalf("found job from wrong user: %+v", j)
		}
	}
}
