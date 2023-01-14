package polai

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/exp/maps"
)

type rawEntity struct {
	Uid          string                      `json:"uid"`
	LowerParents []string                    `json:"parents"`
	Attrs        map[string]interface{}      `json:"attrs"`
	EntityId     *complexEntityName          `json:"EntityId"`
	Identifier   *complexEntityName          `json:"Identifier"`
	Parents      []complexEntityName         `json:"Parents"`
	Attributes   map[string]complexAttribute `json:"Attributes"`
}

type complexEntityName struct {
	EntityID   string `json:"EntityId"`
	EntityType string `json:"EntityType"`
}

type complexAttribute struct {
	String  *string `json:"String"`
	Long    *int64  `json:"Long"`
	Boolean *bool   `json:"Boolean"`
	// TODO: more
}

type Entity struct {
	Identifier string
	Parents    []string
	Attributes []Attribute
}

type Attribute struct {
	Name         string
	StringValue  *string
	LongValue    *int64
	BooleanValue *bool
	// TODO: more
}

// EntityStore represents the complete set of known entities within the system.
type EntityStore struct {
	r        *bufio.Reader
	entities *[]Entity
}

// NewEntityStore returns a new instance of EntityStore.
func NewEntityStore(r io.Reader) *EntityStore {
	return &EntityStore{r: bufio.NewReader(r)}
}

// SetEntities overrides all entities.
func (e *EntityStore) SetEntities(r io.Reader) {
	e.r = bufio.NewReader(r)
	e.entities = nil
}

// GetEntities retrieves all entities.
func (e *EntityStore) GetEntities() ([]Entity, error) {
	if e.entities == nil {
		b, err := e.r.ReadBytes(byte(eof))
		if err != nil {
			return nil, err
		}

		var rawEntities []rawEntity
		if err := json.Unmarshal(b, &rawEntities); err != nil {
			return nil, err
		}

		var entities []Entity
		for _, rawEntity := range rawEntities {
			if rawEntity.EntityId != nil {
				rawEntity.Identifier = rawEntity.EntityId
			}

			if rawEntity.Uid != "" {
				var attributes []Attribute
				for attrName, attrVal := range rawEntity.Attrs {
					attribute := Attribute{
						Name: attrName,
					}

					switch attrVal.(type) {
					case int:
						val := int64(attrVal.(int))
						attribute.LongValue = &val
					case int64:
						val := attrVal.(int64)
						attribute.LongValue = &val
					case string:
						val := attrVal.(string)
						attribute.StringValue = &val
					case bool:
						val := attrVal.(bool)
						attribute.BooleanValue = &val
					default:
						return nil, fmt.Errorf("unknown type in attribute block")
					}

					attributes = append(attributes, attribute)
				}

				entities = append(entities, Entity{
					Identifier: rawEntity.Uid,
					Parents:    rawEntity.LowerParents,
					Attributes: attributes,
				})
			} else if rawEntity.Identifier != nil {
				b, _ := json.Marshal(rawEntity.Identifier.EntityID)
				entity := Entity{
					Identifier: fmt.Sprintf("%s::%s", rawEntity.Identifier.EntityType, string(b)),
				}

				for _, parent := range rawEntity.Parents {
					b, _ := json.Marshal(parent.EntityID)
					entity.Parents = append(entity.Parents, fmt.Sprintf("%s::%s", parent.EntityType, string(b)))
				}

				for attrName, attrVal := range rawEntity.Attributes {
					// TODO: validate only one field set
					entity.Attributes = append(entity.Attributes, Attribute{
						Name:         attrName,
						BooleanValue: attrVal.Boolean,
						StringValue:  attrVal.String,
						LongValue:    attrVal.Long,
					})
				}

				entities = append(entities, entity)
			} else {
				return nil, fmt.Errorf("no entity identifier found in entity list item")
			}
		}

		e.entities = &entities
	}

	return *e.entities, nil
}

// GetEntityDescendents retrieves all entities that match or are descendents of those passed in.
func (e *EntityStore) GetEntityDescendents(parents []string) ([]Entity, error) {
	baseEntities, err := e.GetEntities()
	if err != nil {
		return nil, err
	}

	var foundEntities map[string]Entity // using map[string] for dedup purposes
	i := 0
	for i < len(parents) {
		parent := parents[i]
		for _, baseEntity := range baseEntities {
			for _, baseEntityParent := range baseEntity.Parents {
				if baseEntityParent == parent && !contains(parents, baseEntity.Identifier) {
					parents = append(parents, baseEntity.Identifier)
				}
			}
			if baseEntity.Identifier == parent {
				foundEntities[baseEntity.Identifier] = baseEntity
			}
		}
		i++
	}

	return maps.Values(foundEntities), nil
}
