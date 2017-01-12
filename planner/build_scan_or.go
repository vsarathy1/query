//  Copyright (c) 2014 Couchbase, Inc.
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
//  except in compliance with the License. You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the
//  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
//  either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

package planner

import (
	"github.com/couchbase/query/algebra"
	"github.com/couchbase/query/datastore"
	"github.com/couchbase/query/expression"
	"github.com/couchbase/query/plan"
)

func (this *builder) buildOrScan(node *algebra.KeyspaceTerm, id expression.Expression,
	pred *expression.Or, limit expression.Expression, indexes []datastore.Index,
	primaryKey expression.Expressions, formalizer *expression.Formalizer) (
	plan.SecondaryScan, int, error) {

	tryPushdowns := this.cover != nil || this.limit != nil

	if tryPushdowns {
		return this.buildOrScanTryPushdowns(node, id, pred, limit, indexes, primaryKey, formalizer)
	} else {
		return this.buildOrScanNoPushdowns(node, id, pred, limit, indexes, primaryKey, formalizer)
	}
}

func (this *builder) buildOrScanTryPushdowns(node *algebra.KeyspaceTerm, id expression.Expression,
	pred *expression.Or, limit expression.Expression, indexes []datastore.Index,
	primaryKey expression.Expressions, formalizer *expression.Formalizer) (
	plan.SecondaryScan, int, error) {

	coveringScans := this.coveringScans

	scan, sargLength, err := this.buildTermScan(node, id, pred, limit, indexes, primaryKey, formalizer)
	if err != nil {
		return nil, 0, err
	}

	if scan != nil {
		foundPushdown := len(this.coveringScans) > len(coveringScans) || this.countScan != nil ||
			this.order != nil || this.limit != nil

		if foundPushdown {
			return scan, sargLength, nil
		}
	}

	return this.buildOrScanNoPushdowns(node, id, pred, limit, indexes, primaryKey, formalizer)
}

func (this *builder) buildOrScanNoPushdowns(node *algebra.KeyspaceTerm, id expression.Expression,
	pred *expression.Or, limit expression.Expression, indexes []datastore.Index,
	primaryKey expression.Expressions, formalizer *expression.Formalizer) (
	plan.SecondaryScan, int, error) {

	where := this.where
	cover := this.cover
	defer func() {
		this.where = where
		this.cover = cover
	}()

	this.cover = nil
	this.resetCountMin()

	if this.order != nil {
		this.resetOrderLimit()
		limit = nil
	}

	var buf [16]plan.SecondaryScan
	var scans []plan.SecondaryScan
	if len(pred.Operands()) <= len(buf) {
		scans = buf[0:0]
	} else {
		scans = make([]plan.SecondaryScan, 0, len(pred.Operands()))
	}

	minSargLength := 0

	for _, op := range pred.Operands() {
		this.where = op
		scan, termSargLength, err := this.buildTermScan(node, id, op, limit, indexes, primaryKey, formalizer)
		if scan == nil || err != nil {
			return nil, 0, err
		}

		scans = append(scans, scan)

		if minSargLength == 0 || minSargLength > termSargLength {
			minSargLength = termSargLength
		}
	}

	rv := plan.NewUnionScan(scans...)
	return rv.Streamline(), minSargLength, nil
}