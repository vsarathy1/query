//  Copyright (c) 2017 Couchbase, Inc.
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

	"github.com/couchbase/query/algebra"
	"github.com/couchbase/query/expression"
	"github.com/couchbase/query/expression/parser"
)

type NLJoin struct {
	readonly
	outer       bool
	alias       string
	onclause    expression.Expression
	hintError   string
	child       Operator
	filter      expression.Expression
	cost        float64
	cumCost     float64
	cardinality float64
}

func NewNLJoin(join *algebra.AnsiJoin, child Operator, filter expression.Expression,
	cost, cardinality float64) *NLJoin {
	return &NLJoin{
		outer:       join.Outer(),
		alias:       join.Alias(),
		onclause:    join.Onclause(),
		hintError:   join.HintError(),
		child:       child,
		filter:      filter,
		cost:        cost,
		cumCost:     0,
		cardinality: cardinality,
	}
}

func NewNLJoinJE(child Operator, outer bool, onClause expression.Expression, alias string, filter expression.Expression,
	cost, cumCost, cardinality float64) *NLJoin {
	return &NLJoin{
		outer:       outer,
		alias:       alias,
		onclause:    onClause,
		hintError:   "",
		child:       child,
		filter:      filter,
		cost:        cost,
		cumCost:     cumCost,
		cardinality: cardinality,
	}
}

func (this *NLJoin) Accept(visitor Visitor) (interface{}, error) {
	return visitor.VisitNLJoin(this)
}

func (this *NLJoin) New() Operator {
	return &NLJoin{}
}

func (this *NLJoin) Outer() bool {
	return this.outer
}

func (this *NLJoin) Alias() string {
	return this.alias
}

func (this *NLJoin) Onclause() expression.Expression {
	return this.onclause
}

func (this *NLJoin) HintError() string {
	return this.hintError
}

func (this *NLJoin) Child() Operator {
	return this.child
}

func (this *NLJoin) SetHintError(hintErr string) {
	this.hintError = hintErr
}

func (this *NLJoin) Filter() expression.Expression {
	return this.filter
}

func (this *NLJoin) Cost() float64 {
	if this.cumCost > 0 {
		return this.cumCost // to maintain compatibility between new join enum code and current explain
	} else {
		return this.cost
	}
}

func (this *NLJoin) CumCost() float64 {
	return this.cumCost
}

func (this *NLJoin) Cardinality() float64 {
	return this.cardinality
}

func (this *NLJoin) MarshalJSON() ([]byte, error) {
	return json.Marshal(this.MarshalBase(nil))
}

func (this *NLJoin) MarshalBase(f func(map[string]interface{})) map[string]interface{} {
	r := map[string]interface{}{"#operator": "NestedLoopJoin"}
	r["alias"] = this.alias
	r["on_clause"] = expression.NewStringer().Visit(this.onclause)

	if this.outer {
		r["outer"] = this.outer
	}

	if this.hintError != "" {
		r["hint_not_followed"] = this.hintError
	}

	if this.filter != nil {
		r["filter"] = expression.NewStringer().Visit(this.filter)
	}

	if this.cost > 0.0 {
		r["cost"] = this.cost
	}

	if this.cardinality > 0.0 {
		r["cardinality"] = this.cardinality
	}

	if f != nil {
		f(r)
	} else {
		r["~child"] = this.child
	}
	return r
}

func (this *NLJoin) UnmarshalJSON(body []byte) error {
	var _unmarshalled struct {
		_           string          `json:"#operator"`
		Onclause    string          `json:"on_clause"`
		Outer       bool            `json:"outer"`
		Alias       string          `json:"alias"`
		HintError   string          `json:"hint_not_followed"`
		Filter      string          `json:"filter"`
		Cost        float64         `json:"cost"`
		Cardinality float64         `json:"cardinality"`
		Child       json.RawMessage `json:"~child"`
	}

	err := json.Unmarshal(body, &_unmarshalled)
	if err != nil {
		return err
	}

	if _unmarshalled.Onclause != "" {
		this.onclause, err = parser.Parse(_unmarshalled.Onclause)
		if err != nil {
			return err
		}
	}

	this.outer = _unmarshalled.Outer
	this.alias = _unmarshalled.Alias
	this.hintError = _unmarshalled.HintError

	if _unmarshalled.Filter != "" {
		this.filter, err = parser.Parse(_unmarshalled.Filter)
		if err != nil {
			return err
		}
	}

	this.cost = getCost(_unmarshalled.Cost)
	this.cardinality = getCardinality(_unmarshalled.Cardinality)

	raw_child := _unmarshalled.Child
	var child_type struct {
		Op_name string `json:"#operator"`
	}

	err = json.Unmarshal(raw_child, &child_type)
	if err != nil {
		return err
	}

	this.child, err = MakeOperator(child_type.Op_name, raw_child)
	if err != nil {
		return err
	}

	return nil
}

func (this *NLJoin) verify(prepared *Prepared) bool {
	return this.child.verify(prepared)
}
