package pgsql

import (
	"github.com/MXi4oyu/DockerXScan/common/commonerr"
	"github.com/MXi4oyu/DockerXScan/database"
)

//插入一条namespace数据
func (pgSQL *pgSQL)InsertNamespace(namespace database.Namespace) (int ,error)  {

	if namespace.Name==""{
		return 0,commonerr.NewBadRequestError("could not find/insert invalid Namespace")
	}

	if pgSQL.cache !=nil{
		if id, found := pgSQL.cache.Get("namespace:" + namespace.Name); found {
			return id.(int),nil
		}
	}

	var id int
	err:=pgSQL.QueryRow(soiNamespace,namespace.Name,namespace.VersionFormat).Scan(&id)
	if err != nil {
		return 0, handleError("soiNamespace", err)
	}

	if pgSQL.cache != nil {
		pgSQL.cache.Add("namespace:"+namespace.Name, id)
	}

	return id, nil

}

func (pgSQL *pgSQL) ListNamespaces()  (namespaces []database.Namespace, err error) {
	rows, err := pgSQL.Query(listNamespace)

	if err != nil {
		return namespaces, handleError("listNamespace", err)
	}
	defer rows.Close()

	if rows.Next(){
		var ns database.Namespace
		err = rows.Scan(&ns.ID,&ns.Name,ns.VersionFormat)
		if err != nil {
			return namespaces, handleError("listNamespace.Scan()", err)
		}

		namespaces = append(namespaces, ns)
	}

	if err = rows.Err(); err != nil {
		return namespaces, handleError("listNamespace.Rows()", err)
	}

	return  namespaces,err

}
