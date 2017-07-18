package pgsql

import (
	"database/sql"
	"net/url"
	"log"
	"strings"
	"fmt"
	"io/ioutil"
	"gopkg.in/yaml.v2"
	"github.com/lib/pq"
	"github.com/MXi4oyu/DockerXScan/common/commonerr"
	"github.com/MXi4oyu/DockerXScan/database"
	"github.com/hashicorp/golang-lru"
)

func init()  {
	//注册数据库驱动
	database.Register("pgsql", openDatabase)
	fmt.Println("init pgsql")
}

type Queryer interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

type pgSQL struct {
	*sql.DB
	cache  *lru.ARCCache
	config Config
}

// Close closes the database and destroys if ManageDatabaseLifecycle has been specified in
// the configuration.
func (pgSQL *pgSQL) Close() {
	if pgSQL.DB != nil {
		pgSQL.DB.Close()
	}

	if pgSQL.config.ManageDatabaseLifecycle {
		dbName, pgSourceURL, _ := parseConnectionString(pgSQL.config.Source)
		dropDatabase(pgSourceURL, dbName)
	}
}

// Ping verifies that the database is accessible.
func (pgSQL *pgSQL) Ping() bool {
	return pgSQL.DB.Ping() == nil
}

// Config is the configuration that is used by openDatabase.
type Config struct {
	Source    string
	CacheSize int

	ManageDatabaseLifecycle bool
	FixturePath             string
}


func openDatabase(registrableComponentConfig database.RegistrableComponentConfig) (database.Datastore, error) {
	var pg pgSQL
	var err error

	// Parse configuration.
	pg.config = Config{
		CacheSize: 16384,
	}
	bytes, err := yaml.Marshal(registrableComponentConfig.Options)
	if err != nil {
		return nil, fmt.Errorf("pgsql: could not load configuration: %v", err)
	}
	err = yaml.Unmarshal(bytes, &pg.config)
	if err != nil {
		return nil, fmt.Errorf("pgsql: could not load configuration: %v", err)
	}

	dbName, pgSourceURL, err := parseConnectionString(pg.config.Source)
	if err != nil {
		return nil, err
	}

	// Create database.
	if pg.config.ManageDatabaseLifecycle {
		log.Println("pgsql: creating database")
		if err = createDatabase(pgSourceURL, dbName); err != nil {
			return nil, err
		}
	}

	// Open database.
	pg.DB, err = sql.Open("postgres", pg.config.Source)
	if err != nil {
		pg.Close()
		return nil, fmt.Errorf("pgsql: could not open database: %v", err)
	}

	// Verify database state.
	if err = pg.DB.Ping(); err != nil {
		pg.Close()
		return nil, fmt.Errorf("pgsql: could not open database: %v", err)
	}

	// Load fixture data.
	if pg.config.FixturePath != "" {
		log.Println("pgsql: loading fixtures")

		d, err := ioutil.ReadFile(pg.config.FixturePath)
		if err != nil {
			pg.Close()
			return nil, fmt.Errorf("pgsql: could not open fixture file: %v", err)
		}

		_, err = pg.DB.Exec(string(d))
		if err != nil {
			pg.Close()
			return nil, fmt.Errorf("pgsql: an error occured while importing fixtures: %v", err)
		}
	}
	// Initialize cache.
	// TODO(Quentin-M): Benchmark with a simple LRU Cache.
	if pg.config.CacheSize > 0 {
		pg.cache, _ = lru.NewARC(pg.config.CacheSize)
	}

	//return &pg, nil
	return nil,nil
}

func parseConnectionString(source string) (dbName string, pgSourceURL string, err error) {
	if source == "" {
		return "", "", commonerr.NewBadRequestError("pgsql: no database connection string specified")
	}

	sourceURL, err := url.Parse(source)
	if err != nil {
		return "", "", commonerr.NewBadRequestError("pgsql: database connection string is not a valid URL")
	}

	dbName = strings.TrimPrefix(sourceURL.Path, "/")

	pgSource := *sourceURL
	pgSource.Path = "/postgres"
	pgSourceURL = pgSource.String()

	return
}


func createDatabase(source, dbName string) error {
	// Open database.
	db, err := sql.Open("postgres", source)
	if err != nil {
		return fmt.Errorf("pgsql: could not open 'postgres' database for creation: %v", err)
	}
	defer db.Close()

	// Create database.
	_, err = db.Exec("CREATE DATABASE " + dbName)
	if err != nil {
		return fmt.Errorf("pgsql: could not create database: %v", err)
	}

	return nil
}


func dropDatabase(source, dbName string) error {
	// Open database.
	db, err := sql.Open("postgres", source)
	if err != nil {
		return fmt.Errorf("could not open database (DropDatabase): %v", err)
	}
	defer db.Close()

	// Kill any opened connection.
	if _, err = db.Exec(`
    SELECT pg_terminate_backend(pg_stat_activity.pid)
    FROM pg_stat_activity
    WHERE pg_stat_activity.datname = $1
    AND pid <> pg_backend_pid()`, dbName); err != nil {
		return fmt.Errorf("could not drop database: %v", err)
	}

	// Drop database.
	if _, err = db.Exec("DROP DATABASE " + dbName); err != nil {
		return fmt.Errorf("could not drop database: %v", err)
	}

	return nil
}


func handleError(desc string, err error) error {
	if err == nil {
		return nil
	}

	if err == sql.ErrNoRows {
		return commonerr.ErrNotFound
	}

	if _, o := err.(*pq.Error); o || err == sql.ErrTxDone || strings.HasPrefix(err.Error(), "sql:") {
		return commonerr.ErrBackendException
	}

	return err
}

// isErrUniqueViolation determines is the given error is a unique contraint violation.
func isErrUniqueViolation(err error) bool {
	pqErr, ok := err.(*pq.Error)
	return ok && pqErr.Code == "23505"
}