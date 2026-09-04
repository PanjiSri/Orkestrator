package models

import (
	"log"
	"time"

	"github.com/fadhilkurnia/xdn-todo-go/src/config"
	"gorm.io/gorm"
)

var db *gorm.DB

type Task struct {
	Item    string `gorm:"primaryKey" json:"item"`
	Counter int    `json:"counter"`
}

func init() {
	config.Connect()
	db = config.GetDB()
	migrateWithRetry()
}

func migrateWithRetry() {
	const maxAttempts = 10
	waitTime := 500 * time.Millisecond
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := db.AutoMigrate(&Task{}); err == nil {
			return
		} else if attempt == maxAttempts {
			log.Panicf("failed to migrate task datastore after %d attempts: %v", maxAttempts, err)
		} else {
			log.Printf("failed to migrate task datastore (attempt %d/%d): %v", attempt, maxAttempts, err)
		}

		time.Sleep(waitTime)
		waitTime *= 2
	}
}

func GetActiveTasks() []string {
	var items []string
	result := db.Raw("SELECT item FROM tasks WHERE counter > 0 ORDER BY item ASC").Scan(&items)
	if result.Error != nil {
		log.Println("Error fetching tasks:", result.Error)
	}
	return items
}

func GetTask(item string) (*Task, error) {
	var task Task
	result := db.Where("item = ? AND counter > 0", item).First(&task)
	if result.Error != nil {
		return nil, result.Error
	}
	return &task, nil
}

func AddTask(item string) error {
	return changeTaskCounter(item, 1)
}

func RemoveTask(item string) error {
	return changeTaskCounter(item, -1)
}

func changeTaskCounter(item string, delta int) error {
	query := "INSERT INTO tasks (item, counter) VALUES (?, ?) " +
		"ON CONFLICT(item) DO UPDATE SET counter = tasks.counter + excluded.counter"
	if db.Dialector.Name() == "mysql" {
		query = "INSERT INTO tasks (item, counter) VALUES (?, ?) " +
			"ON DUPLICATE KEY UPDATE counter = counter + VALUES(counter)"
	}

	if b := config.GetWriteBatcher(); b != nil {
		return b.Submit(query, item, delta)
	}
	return db.Exec(query, item, delta).Error
}
