//  Copyright (c) 2019 Couchbase, Inc.
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
//  except in compliance with the License. You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the
//  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
//  either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.
//
// +build !enterprise

package planner

import (
	"github.com/couchbase/query/algebra"
	"github.com/couchbase/query/datastore"
	"github.com/couchbase/query/errors"
	"github.com/couchbase/query/expression"
	"github.com/couchbase/query/plan"
	base "github.com/couchbase/query/plannerbase"
)

func checkCostModel(featureControls uint64) {
	// no-op
}

func optDocCount(keyspace datastore.Keyspace) float64 {
	return OPT_CARD_NOT_AVAIL
}

func optExprSelec(keyspaces map[string]string, pred expression.Expression, advisorValidate bool) (
	float64, float64) {
	return OPT_SELEC_NOT_AVAIL, OPT_SELEC_NOT_AVAIL
}

func optDefInSelec(keyspace, key string, advisorValidate bool) float64 {
	return OPT_SELEC_NOT_AVAIL
}

func optDefLikeSelec(keyspace, key string, advisorValidate bool) float64 {
	return OPT_SELEC_NOT_AVAIL
}

func optMarkIndexFilters(keys expression.Expressions, spans plan.Spans2,
	condition expression.Expression, filters base.Filters) {
	// no-op
}

func optMinCost() float64 {
	return OPT_COST_NOT_AVAIL
}

func primaryIndexScanCost(primary datastore.PrimaryIndex, requestId string) (cost, cardinality float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func indexScanCost(index datastore.Index, sargKeys expression.Expressions, requestId string,
	spans SargSpans, alias string, advisorValidate bool) (cost float64, sel float64, card float64, err error) {
	return OPT_COST_NOT_AVAIL, OPT_SELEC_NOT_AVAIL, OPT_CARD_NOT_AVAIL, errors.NewPlanInternalError("indexScanCost: unexpected in community edition")
}

func getIndexProjectionCost(index datastore.Index, indexProjection *plan.IndexProjection,
	cardinality float64) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getIndexGroupAggsCost(index datastore.Index, indexGroupAggs *plan.IndexGroupAggregates,
	indexProjection *plan.IndexProjection, keyspaces map[string]string,
	cardinality float64) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getKeyScanCost(keys expression.Expression) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getFetchCost(keyspace datastore.Keyspace, cardinality float64) float64 {
	return OPT_COST_NOT_AVAIL
}

func getDistinctScanCost(index datastore.Index, cardinality float64) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getExpressionScanCost(expr expression.Expression, keyspaces map[string]string) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getValueScanCost(pairs algebra.Pairs) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getDummyScanCost() (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getCountScanCost() (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getNLJoinCost(left, right plan.Operator, filters base.Filters, outer bool, op string) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getHashJoinCost(left, right plan.Operator, buildExprs, probeExprs expression.Expressions,
	buildRight, force bool, filters base.Filters, outer bool, op string) (float64, float64, bool) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, false
}

func getNLJoinCost2(left, right plan.Operator, joinCardinality float64, outer bool, op string) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getHashJoinCost2(left, right plan.Operator, buildExprs, probeExprs expression.Expressions,
	joinCardinality float64, buildRight, force bool, outer bool, op string) (float64, float64, bool) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, false
}

func getLookupJoinCost(left plan.Operator, outer bool, right *algebra.KeyspaceTerm,
	rightKeyspace *base.BaseKeyspace) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getLookupJoinCost2(left plan.Operator, outer bool, right *algebra.KeyspaceTerm,
	rightKeyspace *base.BaseKeyspace) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getIndexJoinCost(left plan.Operator, outer bool, right *algebra.KeyspaceTerm,
	rightKeyspace *base.BaseKeyspace, covered bool, index datastore.Index,
	requestId string, advisorValidate bool) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getLookupNestCost(left plan.Operator, outer bool, right *algebra.KeyspaceTerm,
	rightKeyspace *base.BaseKeyspace) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getIndexNestCost(left plan.Operator, outer bool, right *algebra.KeyspaceTerm,
	rightKeyspace *base.BaseKeyspace, index datastore.Index, requestId string, advisorValidate bool) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getUnnestCost(node *algebra.Unnest, lastOp plan.Operator, keyspaces map[string]string, advisorValidate bool) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getSimpleFromTermCost(left, right plan.Operator, filters base.Filters) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getSimpleFromTermCost2(left, right plan.Operator, joinCardinality float64, filters base.Filters) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getSimpleFilterCost(cost, cardinality, selec float64) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getFilterCost(lastOp plan.Operator, expr expression.Expression,
	baseKeyspaces map[string]*base.BaseKeyspace, keyspaceNames map[string]string, advisorValidate bool) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getFilterCostWithInput(expr expression.Expression, baseKeyspaces map[string]*base.BaseKeyspace,
	keyspaceNames map[string]string, cost, cardinality float64, advisorValidate bool) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getLetCost(lastOp plan.Operator) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getWithCost(lastOp plan.Operator, with expression.Bindings) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getOffsetCost(lastOp plan.Operator, noffset int64) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getLimitCost(lastOp plan.Operator, nlimit int64) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getUnnestPredSelec(pred expression.Expression, variable string, mapping expression.Expression,
	keyspaces map[string]string, advisorValidate bool) float64 {
	return OPT_SELEC_NOT_AVAIL
}

func optChooseIntersectScan(keyspace datastore.Keyspace, sargables map[datastore.Index]*indexEntry,
	nTerms int, alias string, advisorValidate bool) map[datastore.Index]*indexEntry {
	return sargables
}

func getSortCost(nterms int, cardinality float64, limit, offset int64) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getInitialProjectCost(projection *algebra.Projection, cardinality float64) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getGroupCosts(group *algebra.Group, aggregates algebra.Aggregates, cost, cardinality float64,
	keyspaces map[string]string, maxParallelism int) (
	float64, float64, float64, float64, float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getDistinctCost(terms algebra.ResultTerms, cardinality float64, keyspaces map[string]string, advisorValidate bool) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getUnionDistinctCost(cost, cardinality float64, first, second plan.Operator, compatible bool) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getUnionAllCost(first, second plan.Operator, compatible bool) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getIntersectAllCost(first, second plan.Operator, compatible bool) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getExceptAllCost(first, second plan.Operator, compatible bool) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getInsertCost(keyspace datastore.Keyspace, key, value, options, limit expression.Expression,
	cost, cardinality float64) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getUpsertCost(keyspace datastore.Keyspace, key, value, options expression.Expression,
	cost, cardinality float64) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getDeleteCost(keyspace datastore.Keyspace, limit expression.Expression,
	cost, cardinality float64) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getCloneCost(keyspace datastore.Keyspace, cost, cardinality float64) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getUpdateSetCost(keyspace datastore.Keyspace, set *algebra.Set, cost, cardinality float64) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getUpdateUnsetCost(keyspace datastore.Keyspace, unset *algebra.Unset, cost, cardinality float64) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getUpdateSendCost(keyspace datastore.Keyspace, limit expression.Expression,
	cost, cardinality float64) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}

func getWindowAggCost(aggs algebra.Aggregates, cost, cardinality float64) (float64, float64) {
	return OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL
}
