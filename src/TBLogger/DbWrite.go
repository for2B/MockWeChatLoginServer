package TBLogger

import (
	"database/sql"
	"unsafe"
	"fmt"
)

type DBOutPut struct {
	Db *sql.DB
	Stmt *sql.Stmt
}

func NewDbOutPut(db *sql.DB)* DBOutPut{
		dbOP := &DBOutPut{Db:db}
		if db == nil{
			return nil
		}
		var err error
		dbOP.InitSyslogTable()
		dbOP.Stmt,err = dbOP.Db.Prepare("INSERT INTO syslog(log) VALUES ($1)")
		if err!=nil {
			panic("NewDbOp stmt fail")
		}
	return dbOP
}


func (DbOp *DBOutPut) Write(p []byte) (n int, err error) {
	StrMsg := (*string)(unsafe.Pointer(&p))
	_,err = DbOp.Stmt.Exec(StrMsg)
	if err!=nil{
		fmt.Println("Insert into syslog fail",err)
		return len(p),err
	}
	return len(p), nil
}

func (DbOp *DBOutPut)InitSyslogTable(){
	_, err := DbOp.Db.Exec(`create table if not exists syslog(
		id SERIAL NOT NULL,
		log text NOT NULL,
		PRIMARY KEY ("id")
	);`)
	if err != nil {
		panic("Init syslog table fail")
	}
}

func (DbOp *DBOutPut)Close(){
	DbOp.Stmt.Close()
}

