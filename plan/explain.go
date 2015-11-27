//  Copyright (c) 2014 Couchbase, Inc.
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
//  except in compliance with the License. You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the
//  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
//  either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

package plan

import (
	"encoding/json"
)

type Explain struct {
	readonly
	op Operator
}

func NewExplain(op Operator) *Explain {
	return &Explain{
		op: op,
	}
}

func (this *Explain) Accept(visitor Visitor) (interface{}, error) {
	return visitor.VisitExplain(this)
}

func (this *Explain) New() Operator {
	return &Explain{}
}

func (this *Explain) Operator() Operator {
	return this.op
}

func (this *Explain) MarshalJSON() ([]byte, error) {
	r := map[string]interface{}{"#operator": "Explain"}
	r["op"] = this.op
	return json.Marshal(r)
}

func (this *Explain) UnmarshalJSON(body []byte) error {
	var _unmarshalled struct {
		_  string          `json:"#operator"`
		Op json.RawMessage `json:"op"`
	}

	err := json.Unmarshal(body, &_unmarshalled)
	if err != nil {
		return err
	}

	var op_type struct {
		Operator string `json:"#operator"`
	}

	err = json.Unmarshal(_unmarshalled.Op, &op_type)
	if err != nil {
		return err
	}

	this.op, err = MakeOperator(op_type.Operator, _unmarshalled.Op)
	return err
}
