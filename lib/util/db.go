package util

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
	"log"
	"os"
	"strings"
	"time"
)

var dbCC *gorm.DB
var DbName = "config/scan4all_db"

// close the database connection
func Close() {
	if nil != dbCC {
		if db1, err := dbCC.DB(); nil == err {
			db1.Close()
		}
	}
}

// initialize models
func InitModle(x ...interface{}) {
	if nil == dbCC {
		InitDb()
	}
	dbCC.AutoMigrate(x...)
}

// go - cross-compile go-sqlite3 https://www.modb.pro/db/329524
// ./tools/Check_CVE_2020_26134 -config="/Users/51pwn/MyWork/mybugbounty/allDomains.txt"
// get the Gorm db connection/operation object
func InitDb(dst ...interface{}) *gorm.DB {
	if nil != dbCC {
		log.Println("dbCC not is nil, DbName = ", DbName)
		return dbCC
	}
	szDf := SzPwd + "/" + DbName
	if 1 < len(dst) {
		szDf = dst[1].(string)
	}
	s1 := os.Getenv("DbName")
	if "" != s1 {
		szDf = s1
	}
	s1 = szDf[0:strings.LastIndex(szDf, "/")]
	if "" != s1 {
		Mkdirs(s1)
	}
	log.Println("DbName ", szDf)
	xx01 := sqlite.Open("file:" + szDf + ".db?cache=shared&mode=rwc&_journal_mode=WAL&Synchronous=Off&temp_store=memory&mmap_size=30000000000")
	db, err := gorm.Open(xx01, &gorm.Config{
		PrepareStmt: true,
		Logger:      logger.Default.LogMode(logger.Silent),
		//Logger: logger.Default.LogMode(logger.Info),
	})
	if err == nil { // no error
		db1, _ := db.DB()
		if err := db1.Ping(); nil == err {
			dbCC = db
			db1.SetConnMaxLifetime(time.Minute * 60)
			db1.SetMaxIdleConns(GetValAsInt("MaxIdleConns", 100))
			db1.SetMaxOpenConns(GetValAsInt("MaxOpenConns", 200))
			if nil != dst && 0 < len(dst) {
				db.AutoMigrate(dst[0])
			}
		} else {
			log.Println("sqlite db init Connection failed", err)
		}
	} else {
		//log.Println(err)
	}
	return dbCC
}

// generic
// get the table name of the T type mod
func GetTableName[T any](mod T) string {
	stmt := &gorm.Statement{DB: dbCC}
	stmt.Parse(GetPointVal(mod))
	return stmt.Schema.Table
}

// generic, update
// update the T type mod data by id
func Update[T any](mod *T, query string, args ...interface{}) int64 {
	var t1 *T = mod
	xxxD := dbCC.Table(GetTableName(mod)).Model(&t1)
	xxxD.AutoMigrate(t1)
	rst := xxxD.Where(query, args...).Updates(mod)
	xxxD.Commit()
	if 0 >= rst.RowsAffected && nil != rst.Error {
		log.Println(rst.Error)
	}
	return rst.RowsAffected
}

// Insert new data if the update fails, ensuring only one record exists
func UpInsert[T any](mod *T, query string, args ...interface{}) int64 {
	// On conflict, update all columns except the primary key
	if 1 > Update[T](mod, query, args...) { // &&
		if 1 > Create[T](*mod) {
			xx1 := dbCC.Clauses(clause.OnConflict(clause.OnConflict{
				Columns:   []clause.Column{{Name: "addr"}}, // key colume
				UpdateAll: true})).Create(mod)
			return xx1.RowsAffected
		} else {
			return 1
		}
	}
	return 1
}

// generic, insert
func Create[T any](mod ...T) int64 {
	n := int64(0)
	for _, k := range mod {
		xxxD := dbCC.Table(GetTableName(k)).Model(k)
		xxxD.AutoMigrate(k)
		rst := xxxD.Create(&k)
		n = n + rst.RowsAffected
		rst.Commit()
	}

	return n
}

// generic
// get the count of the T type, supports conditions
// get the count with the where of args on the T type table (mod)
func GetCount[T any](mod T, args ...interface{}) int64 {
	var n int64
	x1 := dbCC.Model(&mod)
	if 0 < len(args) {
		x1.Where(args[0], args[1:]...).Count(&n)
	} else {
		x1.Count(&n)
	}
	return n
}

// generic
// query and return one record of the T type table
func GetOne[T any](rst *T, args ...interface{}) *T {
	if nil == rst {
		rst = new(T)
	}
	xxxD := dbCC.Table(GetTableName(rst)).Model(rst)
	xxxD.AutoMigrate(rst)
	rst1 := xxxD.First(rst, args...)
	if 0 == rst1.RowsAffected && nil != rst1.Error {
		//log.Println(rst1.Error)
		return nil
	}
	return rst
}

// generic
// query the T1 type model mode, and preload its child type with preLd
// set nPageSize and the offset
// and other query conditions conds
func GetSubQueryLists[T1, T2 any](mode T1, preLd string, aRst []T2, nPageSize int, Offset int, conds ...interface{}) *[]T2 {
	if "" != preLd {
		dbCC.Model(&mode).Preload(preLd).Limit(nPageSize).Offset(Offset*nPageSize).Order("updated_at DESC").Find(&aRst, conds...)
	} else {
		dbCC.Model(&mode).Limit(nPageSize).Offset(Offset*nPageSize).Order("updated_at DESC").Find(&aRst, conds...)
	}
	return &aRst
}

// single-table query
func Query4Lists[T any](query string, conds ...interface{}) *[]T {
	var t1 T
	var t2 []T
	dbCC.Model(t1).Where(query, conds...).Find(&t2)
	return &t2
}

// generic
// query the T1 type model mode, and preload its child type with preLd
// set nPageSize and the offset
// and other query conditions conds
func GetSubQueryList[T1, T2, T3 any](mode T1, preLd T3, aRst []T2, nPageSize int, Offset int, conds ...interface{}) *[]T2 {
	return GetSubQueryLists(mode, GetTableName(preLd), aRst, nPageSize, Offset, conds...)
}
