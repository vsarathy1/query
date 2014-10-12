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
	"fmt"

	"github.com/couchbaselabs/query/algebra"
)

func (this *builder) VisitMerge(node *algebra.Merge) (interface{}, error) {
	children := make([]Operator, 0, 8)
	subChildren := make([]Operator, 0, 8)
	source := node.Source()

	if source.Select() != nil {
		sel, err := source.Select().Accept(this)
		if err != nil {
			return nil, err
		}

		children = append(children, sel.(Operator))
	} else {
		if source.From() == nil {
			return nil, fmt.Errorf("MERGE missing source.")
		}

		this.children = children
		this.subChildren = subChildren

		_, err := source.From().Accept(this)
		if err != nil {
			return nil, err
		}
	}

	if source.As() != "" {
		subChildren = append(subChildren, NewAlias(source.As()))
	}

	ksref := node.KeyspaceRef()
	keyspace, err := this.getNameKeyspace(ksref.Namespace(), ksref.Keyspace())
	if err != nil {
		return nil, err
	}

	actions := node.Actions()
	var update, delete, insert Operator

	if actions.Update() != nil {
		act := actions.Update()
		ops := make([]Operator, 0, 4)

		if act.Where() != nil {
			ops = append(ops, NewFilter(act.Where()))
		}

		if act.Set() != nil {
			ops = append(ops, NewSet(act.Set()))
		}

		if act.Unset() != nil {
			ops = append(ops, NewUnset(act.Unset()))
		}

		ops = append(ops, NewSendUpdate(keyspace))
		update = NewSequence(ops...)
	}

	if actions.Delete() != nil {
		act := actions.Delete()
		ops := make([]Operator, 0, 4)

		if act.Where() != nil {
			ops = append(ops, NewFilter(act.Where()))
		}

		ops = append(ops, NewSendDelete(keyspace))
		delete = NewSequence(ops...)
	}

	if actions.Insert() != nil {
		act := actions.Insert()
		ops := make([]Operator, 0, 4)

		if act.Where() != nil {
			ops = append(ops, NewFilter(act.Where()))
		}

		ops = append(ops, NewSendInsert(keyspace, node.Key()))
		insert = NewSequence(ops...)
	}

	merge := NewMerge(keyspace, ksref, node.Key(), update, delete, insert)
	subChildren = append(subChildren, merge)

	if node.Returning() != nil {
		subChildren = append(subChildren, NewInitialProject(node.Returning()), NewFinalProject())
	}

	parallel := NewParallel(NewSequence(subChildren...))
	children = append(children, parallel)

	if node.Limit() != nil {
		children = append(children, NewLimit(node.Limit()))
	}

	return NewSequence(children...), nil
}
