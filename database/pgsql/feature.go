package pgsql

import (
	"github.com/MXi4oyu/DockerXScan/database"
	"github.com/MXi4oyu/DockerXScan/common/commonerr"
)

func (pgSQL *pgSQL) InsertFeature(feature database.Feature) (int, error) {
	if feature.Name == "" {
		return 0, commonerr.NewBadRequestError("could not find/insert invalid Feature")
	}

	if pgSQL.cache !=nil{
		id, found := pgSQL.cache.Get("feature:" + feature.Namespace.Name + ":" + feature.Name)
		if found{
			return id.(int), nil
		}
	}

	//查找或创建namespace
	namespaceID, err := pgSQL.InsertNamespace(feature.Namespace)
	if err != nil {
		return 0, err
	}

	//查找或创建特征
	var id int
	err = pgSQL.QueryRow(soiFeature, feature.Name, namespaceID).Scan(&id)
	if err != nil {
		return 0, handleError("soiFeature", err)
	}

	if pgSQL.cache != nil {
		pgSQL.cache.Add("feature:"+feature.Namespace.Name+":"+feature.Name, id)
	}

	return id, nil





}
