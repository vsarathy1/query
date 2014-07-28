//  Copyright (c) 2014 Couchbase, Inc.
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
//  except in compliance with the License. You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the
//  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
//  either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

package n1ql

import (
	"fmt"
	"strings"

	"github.com/couchbaselabs/query/algebra"
)

func Parse(input string) (algebra.Node, error) {
	lex := newLexer(NewLexer(strings.NewReader(input)))
	yyParse(lex)

	if len(lex.errs) > 0 {
		return nil, fmt.Errorf(strings.Join(lex.errs, "\n"))
	} else {
		return lex.node, nil
	}
}

type lexer struct {
	nex  yyLexer
	errs []string
	node algebra.Node
}

func newLexer(nex yyLexer) *lexer {
	return &lexer{
		nex: nex,
		errs: make([]string, 0, 16),
	}
}

func (this *lexer) Lex(lval *yySymType) int {
	return this.nex.Lex(lval)
}

func (this *lexer) Error(s string) {
	this.errs = append(this.errs, s)
}

func (this *lexer) setNode(node algebra.Node) {
	this.node = node
}
