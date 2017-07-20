package pgsql

import (
	"github.com/MXi4oyu/DockerXScan/database"
	"github.com/MXi4oyu/DockerXScan/common/commonerr"
	"github.com/MXi4oyu/DockerXScan/versionfmt"
	"strings"
	"database/sql"
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

//插入特征版本
func (pgSQL *pgSQL) InsertFeatureVersion(fv database.FeatureVersion) (id int, err error){

	err = versionfmt.Valid(fv.Feature.Namespace.VersionFormat, fv.Version)
	if err != nil {
		return 0, commonerr.NewBadRequestError("could not find/insert invalid FeatureVersion")
	}

	cacheIndex := strings.Join([]string{"featureversion", fv.Feature.Namespace.Name, fv.Feature.Name, fv.Version}, ":")

	if pgSQL.cache != nil {

		id, found := pgSQL.cache.Get(cacheIndex)
		if found {
			return id.(int), nil
		}
	}

	featureID, err := pgSQL.InsertFeature(fv.Feature)

	if err != nil {
		return 0, err
	}

	fv.Feature.ID = featureID

	err = pgSQL.QueryRow(searchFeatureVersion, featureID, fv.Version).Scan(&fv.ID)
	if err != nil && err != sql.ErrNoRows {
		return 0, handleError("searchFeatureVersion", err)
	}
	if err == nil {
		if pgSQL.cache != nil {
			pgSQL.cache.Add(cacheIndex, fv.ID)
		}

		return fv.ID, nil
	}


	// Begin transaction.
	tx, err := pgSQL.Begin()
	if err != nil {
		tx.Rollback()
		return 0, handleError("insertFeatureVersion.Begin()", err)
	}

	if err != nil {
		tx.Rollback()
		return 0, handleError("insertFeatureVersion.lockVulnerabilityAffects", err)
	}

	// Find or create FeatureVersion.
	var created bool

	err = tx.QueryRow(soiFeatureVersion, featureID, fv.Version).Scan(&created, &fv.ID)

	if err != nil {
		tx.Rollback()
		return 0, handleError("soiFeatureVersion", err)
	}

	if !created {
		tx.Commit()

		if pgSQL.cache != nil {
			pgSQL.cache.Add(cacheIndex, fv.ID)
		}

		return fv.ID, nil

	}

	err = linkFeatureVersionToVulnerabilities(tx, fv)
	if err != nil {
		tx.Rollback()
		return 0, err
	}

	// Commit transaction.
	err = tx.Commit()
	if err != nil {
		return 0, handleError("insertFeatureVersion.Commit()", err)
	}

	if pgSQL.cache != nil {
		pgSQL.cache.Add(cacheIndex, fv.ID)
	}

	return fv.ID, nil

}

type vulnerabilityAffectsFeatureVersion struct {
	vulnerabilityID int
	fixedInID       int
	fixedInVersion  string
}


func linkFeatureVersionToVulnerabilities(tx *sql.Tx, featureVersion database.FeatureVersion) error{
	rows, err := tx.Query(searchVulnerabilityFixedInFeature, featureVersion.Feature.ID)
	if err != nil {
		return handleError("searchVulnerabilityFixedInFeature", err)
	}
	defer rows.Close()

	var affects []vulnerabilityAffectsFeatureVersion
	for rows.Next() {
		var affect vulnerabilityAffectsFeatureVersion

		err := rows.Scan(&affect.fixedInID, &affect.vulnerabilityID, &affect.fixedInVersion)
		if err != nil {
			return handleError("searchVulnerabilityFixedInFeature.Scan()", err)
		}

		cmp, err := versionfmt.Compare(featureVersion.Feature.Namespace.VersionFormat, featureVersion.Version, affect.fixedInVersion)
		if err != nil {
			return err
		}
		if cmp < 0 {
			affects = append(affects, affect)
		}
	}
	if err = rows.Err(); err != nil {
		return handleError("searchVulnerabilityFixedInFeature.Rows()", err)
	}
	rows.Close()

	// Insert into Vulnerability_Affects_FeatureVersion.
	for _, affect := range affects {
		// TODO(Quentin-M): Batch me.
		_, err := tx.Exec(insertVulnerabilityAffectsFeatureVersion, affect.vulnerabilityID,
			featureVersion.ID, affect.fixedInID)
		if err != nil {
			return handleError("insertVulnerabilityAffectsFeatureVersion", err)
		}
	}

	return nil

}