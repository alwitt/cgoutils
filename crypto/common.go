package crypto

import (
	"github.com/alwitt/goutils"
	"github.com/apex/log"
)

// engineImpl implements Engine interface
type engineImpl struct {
	goutils.Component
}

/*
NewEngine define a new Engine object.

	@param logTags log.Fields - component log tags
	@returns new Engine object
*/
func NewEngine(logTags log.Fields) (Engine, error) {
	instance := &engineImpl{
		Component: goutils.Component{
			LogTags: logTags,
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
			},
		},
	}
	return instance, instance.init()
}
