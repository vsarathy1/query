//  Copyright (c) 2018 Couchbase, Inc.
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
//  except in compliance with the License. You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the
//  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
//  either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

package semantics

import (
	"strings"

	"github.com/couchbase/query/algebra"
	"github.com/couchbase/query/errors"
	"github.com/couchbase/query/value"
)

func (this *SemChecker) visitAggregateFunction(agg algebra.Aggregate) (err error) {

	if this.StmtType() != "SELECT" {
		return errors.NewSemanticsError(nil, "Aggregates/Window functions are allowed in SELECT only")
	}

	aggName := strings.ToUpper(agg.Name())

	// Aggregate syntax has DISTINCT but aggregate doesn't support it
	if agg.HasFlags(algebra.AGGREGATE_DISTINCT) && !algebra.AggregateHasProperty(agg.Name(), algebra.AGGREGATE_ALLOWS_DISTINCT) {
		return errors.NewWindowSemanticError(aggName, "", "DISTINCT is not allowed.",
			"semantics.visit_aggregate_function.flags")
	}

	// Aggregate syntax has RESPECT|IGNORE NULLS but aggregate doesn't support it
	if agg.HasFlags(algebra.AGGREGATE_RESPECTNULLS|algebra.AGGREGATE_IGNORENULLS) &&
		!algebra.AggregateHasProperty(agg.Name(), algebra.AGGREGATE_WINDOW_RESPECTNULLS|algebra.AGGREGATE_WINDOW_IGNORENULLS) {
		return errors.NewWindowSemanticError(aggName, "NULLS clause ", "is not allowed.",
			"semantics.visit_aggregate_function.flags")
	}

	// Aggregate syntax has FROM FIRST|LAST but aggregate doesn't support it
	if agg.HasFlags(algebra.AGGREGATE_FROMFIRST|algebra.AGGREGATE_FROMLAST) &&
		!algebra.AggregateHasProperty(agg.Name(), algebra.AGGREGATE_WINDOW_FROMFIRST|algebra.AGGREGATE_WINDOW_FROMLAST) {
		return errors.NewWindowSemanticError(aggName, "FROM clause ", "is not allowed.",
			"semantics.visit_aggregate_function.flags")
	}

	wTerm := agg.WindowTerm()
	if wTerm == nil {
		if algebra.AggregateHasProperty(aggName, algebra.AGGREGATE_ALLOWS_REGULAR) {
			return nil
		} else {
			return errors.NewWindowSemanticError(aggName, "Requires ", "OVER clause", "semantics.visit_aggregate_function")
		}
	}

	// Window Aggregation is EE feature only
	if !this.hasSemFlag(_SEM_ENTERPRISE) {
		return errors.NewEnterpriseFeature("Window function", "semantics.visit_aggregate_function")
	}

	// Aggregate syntax has second argument check semantics
	if algebra.AggregateHasProperty(agg.Name(), algebra.AGGREGATE_WINDOW_2ND_POSINT) && len(agg.Operands()) > 1 {
		// second argument must be a constant or expression and must evaluate to a positive non zero integer
		op := agg.Operands()[1]
		ok := (op != nil && (op.Static() != nil || algebra.AggregateHasProperty(agg.Name(), algebra.AGGREGATE_WINDOW_2ND_DYNAMIC)))
		if ok {
			val := op.Value()
			ok = (val == nil || (val.Type() == value.NUMBER && val.(value.NumberValue).Float64() >= 0.0 &&
				value.IsInt(val.(value.NumberValue).Float64())))
		}

		if !ok {
			return errors.NewWindowSemanticError(aggName, "", "second value must be positive non zero integer.",
				"semantics.visit_aggregate_function.window")
		}
	}

	oby := wTerm.OrderBy()
	windowFrame := wTerm.WindowFrame()

	if oby != nil && algebra.AggregateHasProperty(agg.Name(), algebra.AGGREGATE_WINDOW_NOORDER) {
		// Window function will not allow ORDER BY clause
		return errors.NewWindowSemanticError(aggName, "ORDER BY clause ", "is not allowed.",
			"semantics.visit_aggregate_function.oby")
	}

	// pby, oby, window frame clauses can be absent
	if oby == nil || windowFrame == nil {
		if windowFrame != nil {
			// Without ORDER BY clause window frame is not allowed
			return errors.NewWindowSemanticError(aggName, "window frame ", "is not allowed without ORDER BY.",
				"semantics.visit_aggregate_function.windowframe")
		} else if oby == nil && algebra.AggregateHasProperty(agg.Name(), algebra.AGGREGATE_WINDOW_ORDER) {
			// ORDER BY clause is required
			return errors.NewWindowSemanticError(aggName, "ORDER BY clause ", "is required.",
				"semantics.visit_aggregate_function.oby")
		}
		return nil
	}

	if !algebra.AggregateHasProperty(agg.Name(), algebra.AGGREGATE_ALLOWS_WINDOW_FRAME) {
		// window function will not allow window frame
		return errors.NewWindowSemanticError(aggName, "window frame ", "is not allowed.",
			"semantics.visit_aggregate_function.windowframe")
	}

	wfes := windowFrame.WindowFrameExtents()
	between := wfes[0].HasModifier(algebra.WINDOW_FRAME_BETWEEN)
	if between {
		if wfes[0].HasModifier(algebra.WINDOW_FRAME_UNBOUNDED_FOLLOWING) ||
			wfes[1].HasModifier(algebra.WINDOW_FRAME_UNBOUNDED_PRECEDING) {
			/*
			 * In BETWEEN caluse
			 * UNBOUNDED FOLLOWING is not allowed in start
			 * UNBOUNDED PRECEDING is not allowed in end
			 */
			return errors.NewWindowSemanticError(aggName, "invlaid window frame.", "",
				"semantics.visit_aggregate_function.windowframe")
		}

		if (wfes[1].HasModifier(algebra.WINDOW_FRAME_VALUE_PRECEDING) &&
			!wfes[0].HasModifier(algebra.WINDOW_FRAME_VALUE_PRECEDING|algebra.WINDOW_FRAME_UNBOUNDED_PRECEDING)) ||
			(wfes[0].HasModifier(algebra.WINDOW_FRAME_VALUE_FOLLOWING) &&
				!wfes[1].HasModifier(algebra.WINDOW_FRAME_VALUE_FOLLOWING|algebra.WINDOW_FRAME_UNBOUNDED_FOLLOWING)) {
			/*
			 * If value_expr FOLLOWING is the start point, then the end point must be value_expr FOLLOWING or UNBOUNDED FOLLOWING.
			 * If value_expr PRECEDING is the end point, then the start point must be value_expr PRECEDING or UNBOUNDED PRECEDING.
			 * Above rules automatically covers following
			 *       As a start point, CURRENT ROW then end point cannot be value_expr PRECEDING.
			 *       As a end point point, CURRENT ROW then start point cannot be value_expr FOLLOWING..
			 */
			return errors.NewWindowSemanticError(aggName, "invlaid window frame.", "",
				"semantics.visit_aggregate_function.windowframe")
		}
	} else if wfes[0].HasModifier(algebra.WINDOW_FRAME_UNBOUNDED_FOLLOWING | algebra.WINDOW_FRAME_VALUE_FOLLOWING) {
		// UNBOUNDED FOLLOWING, value_expr FOLLOWING allowed only in BETWEEN clause
		return errors.NewWindowSemanticError(aggName, "invlaid frame.", "", "semantics.visit_aggregate_function.windowframe")
	}

	for _, wfe := range wfes {
		if wfe.HasModifier(algebra.WINDOW_FRAME_VALUE_FOLLOWING | algebra.WINDOW_FRAME_VALUE_PRECEDING) {

			// value_expr must be a constant or expression and must evaluate to a positive numeric value.
			valExpr := wfe.ValueExpression()
			ok := (valExpr != nil && valExpr.Static() != nil)
			if ok {
				val := valExpr.Value()
				ok = (val == nil ||
					(val.Type() == value.NUMBER && val.(value.NumberValue).Float64() >= 0.0 &&
						(windowFrame.HasModifier(algebra.WINDOW_FRAME_RANGE) ||
							value.IsInt(val.(value.NumberValue).Float64()))))
			}

			if !ok {
				return errors.NewWindowSemanticError(aggName, "window frame ", "value expression is invalid.",
					"semantics.visit_aggregate_function.windowframe")
			}
		}
	}

	if len(oby.Terms()) > 1 && windowFrame.RangeWindowFrame() {
		/*
		 * The following window frame options only allows multiple ORDER BY terms
		 *
		 * RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW. The short form of this is RANGE UNBOUNDED PRECEDING.
		 * RANGE BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING
		 * RANGE BETWEEN CURRENT ROW AND CURRENT ROW. The short form of this is RANGE CURRENT ROW.
		 * RANGE BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
		 * Above rules automatically covers following
		 *        RANGE with value_expr PRECEDING or value_expr FOLLOWING can have single term in ORDER BY
		 */
		ok := (!between && wfes[0].HasModifier(algebra.WINDOW_FRAME_UNBOUNDED_PRECEDING|algebra.WINDOW_FRAME_CURRENT_ROW)) ||
			(between && wfes[0].HasModifier(algebra.WINDOW_FRAME_UNBOUNDED_PRECEDING|algebra.WINDOW_FRAME_CURRENT_ROW) &&
				wfes[1].HasModifier(algebra.WINDOW_FRAME_CURRENT_ROW|algebra.WINDOW_FRAME_UNBOUNDED_FOLLOWING))
		if !ok {
			return errors.NewWindowSemanticError(aggName, "", "multiple ORDER BY terms are not allowed.",
				"semantics.visit_aggregate_function.oby")
		}
	}

	return nil

}
