package pgsql

import (
	"github.com/MXi4oyu/DockerXScan/database"
	"github.com/MXi4oyu/DockerXScan/common/commonerr"
	"github.com/guregu/null/zero"
	"log"
)

//插入一个镜像层
func (pgSQL *pgSQL)InsertLayer(layer database.Layer) error {

	if layer.Name == "" {
		return commonerr.NewBadRequestError("could not insert a layer which has an empty Name")
	}

	//parentID
	var parentID zero.Int
	parentID = zero.IntFrom(int64(layer.ParentID))

	// Begin transaction.
	tx,err:=pgSQL.Begin()
	if err != nil {
		tx.Rollback()
		return handleError("InsertLayer.Begin()", err)
	}

	if layer.ID==0{

		// Insert a new layer.
		err=tx.QueryRow(insertLayer,layer.Name,parentID).Scan(&layer.ID)

		if err != nil {
			tx.Rollback()
			if isErrUniqueViolation(err) {
				log.Println("Attempted to insert duplicate layer.")
				return nil
			}

			return handleError("insertLayer", err)
		}

		}else {

		_, err = tx.Exec(updateLayer,layer.ID,layer.Name)

		if err != nil {
			tx.Rollback()
			return handleError("updateLayer", err)
		}

	}

	//Commit transaction.
	err = tx.Commit()
	if err != nil {
		tx.Rollback()
		return handleError("InsertLayer.Commit()", err)
	}

	return nil

}
