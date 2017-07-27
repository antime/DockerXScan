package pgsql

import (
	"github.com/MXi4oyu/DockerXScan/database"
	"github.com/MXi4oyu/DockerXScan/common/commonerr"
	"database/sql"
	"strings"
	"time"
	"github.com/guregu/null/zero"
	log "github.com/sirupsen/logrus"
)

//插入一个镜像层
func (pgSQL *pgSQL)InsertLayer(layer database.Layer) error {

	tf := time.Now()

	// Verify parameters
	if layer.Name == "" {
		log.Warning("could not insert a layer which has an empty Name")
		return commonerr.NewBadRequestError("could not insert a layer which has an empty Name")
	}

	// Get a potentially existing layer.
	existingLayer, err := pgSQL.FindLayer(layer.Name, true, false)
	if err != nil && err != commonerr.ErrNotFound {
		return err
	} else if err == nil {
		if existingLayer.EngineVersion >= layer.EngineVersion {
			// The layer exists and has an equal or higher engine version, do nothing.
			return nil
		}

		layer.ID = existingLayer.ID
	}

	// We do `defer observeQueryTime` here because we don't want to observe existing layers.
	defer observeQueryTime("InsertLayer", "all", tf)

	// Get parent ID.
	var parentID zero.Int
	if layer.Parent != nil {
		if layer.Parent.ID == 0 {
			log.Warning("Parent is expected to be retrieved from database when inserting a layer.")
			return commonerr.NewBadRequestError("Parent is expected to be retrieved from database when inserting a layer.")
		}

		parentID = zero.IntFrom(int64(layer.Parent.ID))
	}

	// Find or insert namespace if provided.
	var namespaceID zero.Int
	if layer.Namespace != nil {
		n, err := pgSQL.InsertNamespace(*layer.Namespace)
		if err != nil {
			return err
		}
		namespaceID = zero.IntFrom(int64(n))
	} else if layer.Namespace == nil && layer.Parent != nil {
		// Import the Namespace from the parent if it has one and this layer doesn't specify one.
		if layer.Parent.Namespace != nil {
			namespaceID = zero.IntFrom(int64(layer.Parent.Namespace.ID))
		}
	}

	// Begin transaction.
	tx, err := pgSQL.Begin()
	if err != nil {
		tx.Rollback()
		return handleError("InsertLayer.Begin()", err)
	}

	if layer.ID == 0 {
		// Insert a new layer.
		err = tx.QueryRow(insertLayer, layer.Name, layer.EngineVersion, parentID, namespaceID).
			Scan(&layer.ID)
		if err != nil {
			tx.Rollback()

			if isErrUniqueViolation(err) {
				// Ignore this error, another process collided.
				log.Debug("Attempted to insert duplicate layer.")
				return nil
			}
			return handleError("insertLayer", err)
		}
	} else {
		// Update an existing layer.
		_, err = tx.Exec(updateLayer, layer.ID, layer.EngineVersion, namespaceID)
		if err != nil {
			tx.Rollback()
			return handleError("updateLayer", err)
		}

		// Remove all existing Layer_diff_FeatureVersion.
		_, err = tx.Exec(removeLayerDiffFeatureVersion, layer.ID)
		if err != nil {
			tx.Rollback()
			return handleError("removeLayerDiffFeatureVersion", err)
		}
	}

	// Update Layer_diff_FeatureVersion now.
	err = pgSQL.updateDiffFeatureVersions(tx, &layer, &existingLayer)
	if err != nil {
		tx.Rollback()
		return err
	}

	// Commit transaction.
	err = tx.Commit()
	if err != nil {
		tx.Rollback()
		return handleError("InsertLayer.Commit()", err)
	}

	return nil

}

func (pgSQL *pgSQL) FindLayer(name string, withFeatures, withVulnerabilities bool) (database.Layer, error){

	var(
		layer           database.Layer
		parentID        zero.Int
		parentName      zero.String
	)

	err:=pgSQL.QueryRow(searchLayer,name).Scan(
		&layer.ID,
		&layer.Name,
		&parentID,
		&parentName,
	)

	if err != nil {
		return layer, handleError("searchLayer", err)
	}

	if !parentID.IsZero() {
		layer.Parent = &database.Layer{
			Model: database.Model{ID: int(parentID.Int64)},
			Name:  parentName.String,
		}
	}


	return layer,nil

}


func (pgSQL *pgSQL) updateDiffFeatureVersions(tx *sql.Tx, layer, existingLayer *database.Layer) error {
	// add and del are the FeatureVersion diff we should insert.
	var add []database.FeatureVersion
	var del []database.FeatureVersion

	if layer.Parent == nil {
		// There is no parent, every Features are added.
		add = append(add, layer.Features...)
	} else if layer.Parent != nil {
		// There is a parent, we need to diff the Features with it.

		// Build name:version structures.
		layerFeaturesMapNV, layerFeaturesNV := createNV(layer.Features)
		parentLayerFeaturesMapNV, parentLayerFeaturesNV := createNV(layer.Parent.Features)

		// Calculate the added and deleted FeatureVersions name:version.
		addNV := compareStringLists(layerFeaturesNV, parentLayerFeaturesNV)
		delNV := compareStringLists(parentLayerFeaturesNV, layerFeaturesNV)

		// Fill the structures containing the added and deleted FeatureVersions.
		for _, nv := range addNV {
			add = append(add, *layerFeaturesMapNV[nv])
		}
		for _, nv := range delNV {
			del = append(del, *parentLayerFeaturesMapNV[nv])
		}
	}

	// Insert FeatureVersions in the database.
	addIDs, err := pgSQL.insertFeatureVersions(add)
	if err != nil {
		return err
	}
	delIDs, err := pgSQL.insertFeatureVersions(del)
	if err != nil {
		return err
	}

	// Insert diff in the database.
	if len(addIDs) > 0 {
		_, err = tx.Exec(insertLayerDiffFeatureVersion, layer.ID, "add", buildInputArray(addIDs))
		if err != nil {
			return handleError("insertLayerDiffFeatureVersion.Add", err)
		}
	}
	if len(delIDs) > 0 {
		_, err = tx.Exec(insertLayerDiffFeatureVersion, layer.ID, "del", buildInputArray(delIDs))
		if err != nil {
			return handleError("insertLayerDiffFeatureVersion.Del", err)
		}
	}

	return nil
}

func createNV(features []database.FeatureVersion) (map[string]*database.FeatureVersion, []string) {
	mapNV := make(map[string]*database.FeatureVersion, 0)
	sliceNV := make([]string, 0, len(features))

	for i := 0; i < len(features); i++ {
		fv := &features[i]
		nv := strings.Join([]string{fv.Feature.Namespace.Name, fv.Feature.Name, fv.Version}, ":")
		mapNV[nv] = fv
		sliceNV = append(sliceNV, nv)
	}

	return mapNV, sliceNV
}


//删除一个layer
func (pgSQL *pgSQL) DeleteLayer(name string) error {

	result, err := pgSQL.Exec(removeLayer, name)
	if err != nil {
		return handleError("removeLayer", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return handleError("removeLayer.RowsAffected()", err)
	}

	if affected <= 0 {
		return commonerr.ErrNotFound
	}

	return nil
}

