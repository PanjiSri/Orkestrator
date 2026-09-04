package config

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fadhilkurnia/xdn-todo-go/src/batcher"
	"goki.dev/rqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var db *gorm.DB
var writeBatcher *batcher.Batcher

func Connect() {
	dbType := os.Getenv("DB_TYPE")
	if dbType == "" {
		dbType = "sqlite"
	}
	if dbType != "sqlite" && dbType != "mysql" && dbType != "postgres" && dbType != "rqlite" {
		panic("invalid DB_TYPE, options: sqlite, mysql, postgres, rqlite")
	}

	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		dbHost = "127.0.0.1"
	}

	gormConfig := &gorm.Config{
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
	}
	isDisableTxn := os.Getenv("DISABLE_TXN")
	if isDisableTxn != "" && strings.ToLower(isDisableTxn) == "false" {
		gormConfig = &gorm.Config{}
	}

	log.Println("Using datastore:", dbType)

	switch dbType {
	case "sqlite":
		dataDir := filepath.Join(".", "data")
		os.MkdirAll(dataDir, os.ModePerm)
		dsn := sqliteDSN()
		d, err := gorm.Open(sqlite.Open(dsn), gormConfig)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		db = d
	case "mysql":
		dsn := mysqlDSN(dbHost)
		d, err := openWithRetry(mysql.Open(dsn), gormConfig)
		if err != nil {
			fmt.Println(err)
			panic("failed to connect to database")
		}
		configurePool(d)
		db = d
	case "postgres":
		dsn := postgresDSN(dbHost)
		d, err := openWithRetry(postgres.Open(dsn), gormConfig)
		if err != nil {
			fmt.Println(err)
			panic("failed to connect to database")
		}
		configurePool(d)
		applyPostgresServerSettings(d)
		db = d
	case "rqlite":
		dsn := normalizeRqliteURL(dbHost)
		d, err := gorm.Open(rqlite.Open(dsn), gormConfig)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		db = d

		if strings.ToLower(os.Getenv("ENABLE_RQLITE_BATCHING")) == "true" {
			maxSize := 128
			if v, err := strconv.Atoi(os.Getenv("RQLITE_BATCH_MAX_SIZE")); err == nil && v > 0 {
				maxSize = v
			}
			windowMs := 2
			if v, err := strconv.Atoi(os.Getenv("RQLITE_BATCH_WINDOW_MS")); err == nil && v > 0 {
				windowMs = v
			}
			b, err := batcher.New(dsn, maxSize, windowMs)
			if err != nil {
				log.Printf("WARNING: failed to create write batcher: %v", err)
			} else {
				b.Start()
				writeBatcher = b
			}
		}
	}
}

const (
	defaultMaxOpenConns = 64
	defaultMaxIdleConns = 64
)

func configurePool(d *gorm.DB) {
	sqlDB, err := d.DB()
	if err != nil {
		log.Printf("WARNING: cannot configure connection pool: %v", err)
		return
	}

	maxOpen := envIntOrDefault("DB_MAX_OPEN_CONNS", defaultMaxOpenConns)
	maxIdle := envIntOrDefault("DB_MAX_IDLE_CONNS", defaultMaxIdleConns)
	if maxIdle > maxOpen {

		maxIdle = maxOpen
	}

	sqlDB.SetMaxOpenConns(maxOpen)
	sqlDB.SetMaxIdleConns(maxIdle)

	sqlDB.SetConnMaxLifetime(0)
	log.Printf("connection pool: max_open=%d max_idle=%d", maxOpen, maxIdle)
}

const defaultWalInitZero = "off"

var (
	pgSettingNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	pgSettingValuePattern = regexp.MustCompile(`^[A-Za-z0-9_.\-]+$`)
)

func applyPostgresServerSettings(d *gorm.DB) {
	if !strings.EqualFold(envOrDefault("PG_APPLY_SERVER_SETTINGS", "true"), "true") {
		log.Println("postgres server settings: skipped (PG_APPLY_SERVER_SETTINGS is not true)")
		return
	}

	settings := [][2]string{
		{"wal_init_zero", envOrDefault("PG_WAL_INIT_ZERO", defaultWalInitZero)},
	}
	if extra := os.Getenv("PG_EXTRA_SETTINGS"); extra != "" {
		for _, pair := range strings.Split(extra, ",") {
			name, value, found := strings.Cut(strings.TrimSpace(pair), "=")
			if !found {
				log.Printf("WARNING: ignoring malformed PG_EXTRA_SETTINGS entry %q", pair)
				continue
			}
			settings = append(settings,
				[2]string{strings.TrimSpace(name), strings.TrimSpace(value)})
		}
	}

	sqlDB, err := d.DB()
	if err != nil {
		log.Printf("WARNING: cannot apply postgres server settings: %v", err)
		return
	}

	const (
		maxAttempts = 8
		maxWait     = 2 * time.Second
	)
	waitTime := 250 * time.Millisecond
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := trySetPostgresSettings(sqlDB, settings)
		if err == nil {
			return
		}
		if attempt == maxAttempts {
			log.Printf("WARNING: postgres server settings not applied after %d "+
				"attempts, continuing with server defaults: %v", maxAttempts, err)
			return
		}
		log.Printf("postgres server settings not applied yet (attempt %d/%d): %v",
			attempt, maxAttempts, err)
		time.Sleep(waitTime)
		if waitTime < maxWait {
			waitTime *= 2
		}
	}
}

func trySetPostgresSettings(sqlDB *sql.DB, settings [][2]string) error {
	for _, setting := range settings {
		name, value := setting[0], setting[1]
		if !pgSettingNamePattern.MatchString(name) ||
			!pgSettingValuePattern.MatchString(value) {
			return fmt.Errorf("refusing to apply %q=%q: unexpected characters",
				name, value)
		}
		if _, err := sqlDB.Exec(
			fmt.Sprintf("ALTER SYSTEM SET %s = '%s'", name, value)); err != nil {
			return fmt.Errorf("ALTER SYSTEM SET %s='%s' (superuser required): %w",
				name, value, err)
		}
	}

	if _, err := sqlDB.Exec("SELECT pg_reload_conf()"); err != nil {
		return fmt.Errorf("pg_reload_conf(): %w", err)
	}

	for _, setting := range settings {
		name, want := setting[0], setting[1]
		got, err := waitForSetting(sqlDB, name, want)
		if err != nil {
			return err
		}
		log.Printf("postgres setting: %s=%s", name, got)
	}
	return nil
}

func waitForSetting(sqlDB *sql.DB, name, want string) (string, error) {
	const (
		timeout = 3 * time.Second
		poll    = 100 * time.Millisecond
	)
	deadline := time.Now().Add(timeout)
	for {
		var got string
		if err := sqlDB.QueryRow(fmt.Sprintf("SHOW %s", name)).Scan(&got); err != nil {
			return "", fmt.Errorf("reading back %s: %w", name, err)
		}
		if strings.EqualFold(got, want) {
			return got, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("%s is %q %v after reload, wanted %q",
				name, got, timeout, want)
		}
		time.Sleep(poll)
	}
}

func envIntOrDefault(key string, defaultValue int) int {
	if value, ok := os.LookupEnv(key); ok {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			return parsed
		}
		log.Printf("WARNING: ignoring invalid %s=%q, using %d",
			key, os.Getenv(key), defaultValue)
	}
	return defaultValue
}

func sqliteDSN() string {
	enableWAL := true
	if value := os.Getenv("ENABLE_WAL"); value != "" {
		enableWAL = strings.ToLower(value) == "true"
	}
	if !enableWAL {
		return "file:data/tasks.db"
	}
	return "file:data/tasks.db?_journal_mode=WAL&_synchronous=FULL"
}

func mysqlDSN(dbHost string) string {
	dbPort := envOrDefault("DB_PORT", "3306")
	dbUser := envOrDefault("DB_USER", "root")
	dbPassword := envOrDefault("DB_PASSWORD", "root")
	dbName := envOrDefault("DB_NAME", "tasks")
	return fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		dbUser,
		dbPassword,
		dbHost,
		dbPort,
		dbName,
	)
}

func postgresDSN(dbHost string) string {
	if databaseURL := os.Getenv("DATABASE_URL"); databaseURL != "" {
		return databaseURL
	}

	dbPort := envOrDefault("DB_PORT", "5432")
	dbUser := envOrDefault("DB_USER", "postgres")
	dbPassword := envOrDefault("DB_PASSWORD", "root")
	dbName := envOrDefault("DB_NAME", "tasks")
	dbSSLMode := envOrDefault("DB_SSLMODE", "disable")
	dbTimeZone := envOrDefault("DB_TIMEZONE", "UTC")
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s TimeZone=%s",
		dbHost,
		dbPort,
		dbUser,
		dbPassword,
		dbName,
		dbSSLMode,
		dbTimeZone,
	)
}

func envOrDefault(key string, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return defaultValue
}

func openWithRetry(dialector gorm.Dialector, gormConfig *gorm.Config) (*gorm.DB, error) {
	connAttempt := 10
	waitTime := 500 * time.Millisecond
	var lastErr error
	for connAttempt > 0 {
		d, err := gorm.Open(dialector, gormConfig)
		if err == nil {
			return d, nil
		}
		lastErr = err
		fmt.Println(err)
		fmt.Println("retrying to connect ...")
		time.Sleep(waitTime)
		connAttempt--
		waitTime *= 2
	}
	return nil, lastErr
}

func normalizeRqliteURL(dbHost string) string {
	if strings.HasPrefix(dbHost, "http://") || strings.HasPrefix(dbHost, "https://") {
		return dbHost
	}
	if strings.Contains(dbHost, ":") {
		return fmt.Sprintf("http://%s", dbHost)
	}
	return fmt.Sprintf("http://%s:4001", dbHost)
}

func GetDB() *gorm.DB {
	return db
}

func GetWriteBatcher() *batcher.Batcher {
	return writeBatcher
}
