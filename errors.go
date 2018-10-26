// Copyright (c) 2015, Janoš Guljaš <janos@resenje.org>
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package taint

import "reflect"

// InvalidInjectError defines an error type for invalid inject type.
type InvalidInjectError struct {
	Type reflect.Type
}

func (e *InvalidInjectError) Error() string {
	if e.Type == nil {
		return "taint: inject type is nil"
	}
	if e.Type.Kind() != reflect.Ptr {
		return "taint: inject non-pointer type " + e.Type.String()
	}
	return "taint: inject nil type" + e.Type.String()
}

// FieldRequiredError defines an errors type for missing required field.
type FieldRequiredError struct {
	FieldName string
}

func (e *FieldRequiredError) Error() string {
	return "taint: inject required field " + e.FieldName
}

// InvalidTypeError defines an error type for errors where source
// and destination types are not the same.
type InvalidTypeError struct {
	TypeSrc reflect.Type
	TypeDst reflect.Type
}

func (e *InvalidTypeError) Error() string {
	return "taint: inject source type " + e.TypeSrc.String() + " != destination type " + e.TypeDst.String()
}
