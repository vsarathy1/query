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

	"github.com/couchbase/query/expression"
	"github.com/couchbase/query/expression/parser"
)

// KeyScan is used for USE KEYS clauses.
type KeyScan struct {
	readonly
	keys        expression.Expression
	distinct    bool
	cost        float64
	cardinality float64
}

func NewKeyScan(keys expression.Expression, distinct bool, cost, cardinality float64) *KeyScan {
	keys.SetExprFlag(expression.EXPR_CAN_FLATTEN)
	return &KeyScan{
		keys:        keys,
		distinct:    distinct,
		cost:        cost,
		cardinality: cardinality,
	}
}

func (this *KeyScan) Accept(visitor Visitor) (interface{}, error) {
	return visitor.VisitKeyScan(this)
}

func (this *KeyScan) New() Operator {
	return &KeyScan{}
}

func (this *KeyScan) Keys() expression.Expression {
	return this.keys
}

func (this *KeyScan) Distinct() bool {
	return this.distinct
}

func (this *KeyScan) Cost() float64 {
	return this.cost
}

func (this *KeyScan) Cardinality() float64 {
	return this.cardinality
}

func (this *KeyScan) MarshalJSON() ([]byte, error) {
	return json.Marshal(this.MarshalBase(nil))
}

func (this *KeyScan) MarshalBase(f func(map[string]interface{})) map[string]interface{} {
	r := map[string]interface{}{"#operator": "KeyScan"}
	r["keys"] = expression.NewStringer().Visit(this.keys)
	if this.distinct {
		r["distinct"] = this.distinct
	}
	if this.cost > 0.0 {
		r["cost"] = this.cost
	}
	if this.cardinality > 0.0 {
		r["cardinality"] = this.cardinality
	}
	if f != nil {
		f(r)
	}
	return r
}

func (this *KeyScan) UnmarshalJSON(body []byte) error {
	var _unmarshalled struct {
		_           string  `json:"#operator"`
		Keys        string  `json:"keys"`
		Distinct    bool    `json:"distinct"`
		Cost        float64 `json:"cost"`
		Cardinality float64 `json:"cardinality"`
	}

	err := json.Unmarshal(body, &_unmarshalled)
	if err != nil {
		return err
	}

	if _unmarshalled.Keys != "" {
		this.keys, err = parser.Parse(_unmarshalled.Keys)
		if this.keys != nil {
			this.keys.SetExprFlag(expression.EXPR_CAN_FLATTEN)
		}
		if err != nil {
			return err
		}
	}

	this.distinct = _unmarshalled.Distinct
	this.cost = getCost(_unmarshalled.Cost)
	this.cardinality = getCardinality(_unmarshalled.Cardinality)

	return nil
}
