// Copyright (c) 2015, 2016 Janoš Guljaš <janos@resenje.org>
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package taint

import (
	"reflect"
	"testing"
)

func TestInjectBool(t *testing.T) {
	s := true
	var d bool
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if d != s {
		t.Errorf("%T destination %#v is not set to %#v", d, d, s)
	}
}

func TestInjectString(t *testing.T) {
	s := "test"
	var d string
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if d != s {
		t.Errorf("%T destination %#v is not set to %#v", d, d, s)
	}
}

func TestInjectInt(t *testing.T) {
	s := 42
	var d int
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if d != s {
		t.Errorf("%T destination %#v is not set to %#v", d, d, s)
	}
}

func TestInjectInt64Interface(t *testing.T) {
	var s interface{} = int64(42)
	var d int64
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if d != s {
		t.Errorf("%T destination %#v is not set to %#v", d, d, s)
	}
}

func TestInjectFloat64(t *testing.T) {
	s := 42.0
	var d float64
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if d != s {
		t.Errorf("%T destination %#v is not set to %#v", d, d, s)
	}
}

func TestInjectSliceOfStrings(t *testing.T) {
	s := []interface{}{
		"test1",
		"test2",
	}
	expected := []string{
		"test1",
		"test2",
	}
	var d []string
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, expected) {
		t.Errorf("%T destination %#v is not set to %#v", d, d, expected)
	}
}

func TestInjectArrayOfStrings(t *testing.T) {
	s := [2]string{
		"test1",
		"test2",
	}
	expected := [2]string{
		"test1",
		"test2",
	}
	var d [2]string
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, expected) {
		t.Errorf("%T destination %#v is not set to %#v", d, d, expected)
	}
}

func TestInjectArrayOfInterfacesToArrayOfStrings(t *testing.T) {
	s := [2]interface{}{
		"test1",
		"test2",
	}
	expected := [2]string{
		"test1",
		"test2",
	}
	var d [2]string
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, expected) {
		t.Errorf("%T destination %#v is not set to %#v", d, d, expected)
	}
}

func TestInjectStringToSliceOfStrings(t *testing.T) {
	s := "test1"
	expected := []string{
		"test1",
	}
	var d []string
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, expected) {
		t.Errorf("%T destination %#v is not set to %#v", d, d, expected)
	}
}

func TestInjectIntToSliceOfInts(t *testing.T) {
	s := 100
	expected := []int{
		100,
	}
	var d []int
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, expected) {
		t.Errorf("%T destination %#v is not set to %#v", d, d, expected)
	}
}

func TestInjectIntToSliceOfInterfaces(t *testing.T) {
	s := 101
	expected := []interface{}{
		101,
	}
	var d []interface{}
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, expected) {
		t.Errorf("%T destination %#v is not set to %#v", d, d, expected)
	}
}

func TestInjectSliceOfNestedInterfaces(t *testing.T) {
	s := []interface{}{
		"test1",
		"test2",
		42,
		42.0,
		[]string{
			"sub1",
			"sub2",
		},
		[]bool{
			true,
			false,
		},
	}
	expected := s
	var d []interface{}
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, expected) {
		t.Errorf("%T destination %#v is not set to %#v", d, d, expected)
	}
}

func TestInjectMapOfStrings(t *testing.T) {
	s := map[interface{}]interface{}{
		"test1": "value1",
		"test2": "value1",
	}
	expected := map[string]string{
		"test1": "value1",
		"test2": "value1",
	}

	var d map[string]string
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, expected) {
		t.Errorf("%T destination %#v is not set to %#v", d, d, expected)
	}
}

func TestInjectMapOfFloat64s(t *testing.T) {
	s := map[interface{}]float64{
		"test1": 1.1,
		"test2": 2.5,
	}
	expected := map[string]float64{
		"test1": 1.1,
		"test2": 2.5,
	}

	var d map[string]float64
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, expected) {
		t.Errorf("%T destination %#v is not set to %#v", d, d, expected)
	}
}

type Struct1 struct {
	Test1 string `taint:"test-1"`
	Test2 string `taint:",required"`
	Test3 string `taint:"test-3"`
	Test4 int
	Test5 string `taint:",test-something,test-something-else"`
	Test6 string `taint:"-"`
	Test7 []struct{}
}

type Struct2 struct {
	Test1 string `taint:"test-1"`
	Test2 string `taint:",required"`
	Test4 int
	Test7 []struct{}
}

func TestInjectMapOfStruct1s(t *testing.T) {
	s := map[interface{}]Struct1{
		"test1": {
			Test1: "value1",
			Test2: "value2",
			Test3: "value3",
			Test4: 41,
			Test5: "value5",
		},
		"test2": {
			Test1: "value 1",
			Test2: "value 2",
			Test3: "value 3",
			Test4: 42,
			Test5: "value 5",
		},
	}
	expected := map[string]map[string]interface{}{
		"test1": {
			"test-1": "value1",
			"Test2":  "value2",
			"test-3": "value3",
			"Test4":  41,
			"Test5":  "value5",
			"Test7":  []struct{}(nil),
		},
		"test2": {
			"test-1": "value 1",
			"Test2":  "value 2",
			"test-3": "value 3",
			"Test4":  42,
			"Test5":  "value 5",
			"Test7":  []struct{}(nil),
		},
	}

	var d map[string]map[string]interface{}
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, expected) {
		t.Errorf("%T destination %#v is not set to %#v", d, d, expected)
	}
}

func TestInjectStruct1(t *testing.T) {
	s := map[interface{}]interface{}{
		"test-1": "value1",
		"Test2":  "value1",
		"Test4":  4,
	}
	expected := Struct1{
		Test1: "value1",
		Test2: "value1",
		Test4: 4,
	}

	var d Struct1
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, expected) {
		t.Errorf("%T destination %#v is not set to %#v", d, d, expected)
	}
}

func TestInjectStruct1ToStruct2(t *testing.T) {
	s := Struct1{
		Test1: "value1",
		Test2: "value1",
		Test4: 4,
		Test7: []struct{}{
			{},
			{},
		},
	}
	expected := Struct2{
		Test1: "value1",
		Test2: "value1",
		Test4: 4,
		Test7: []struct{}{
			{},
			{},
		},
	}

	var d Struct2
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, expected) {
		t.Errorf("%T destination %#v is not set to %#v", d, d, expected)
	}
}

func TestInvalidTypeError(t *testing.T) {
	s := "test"
	var d int
	err := Inject(s, &d)
	if _, ok := err.(*InvalidTypeError); !ok {
		t.Errorf("Expected InvalidTypeError, but got %#v", err)
	}
}

func TestInvalidInjectError(t *testing.T) {
	s := ""
	var d string
	err := Inject(s, d)
	if _, ok := err.(*InvalidInjectError); !ok {
		t.Errorf("Expected InvalidInjectError, but got %#v", err)
	}
}

type Struct3 struct {
	Test2 string `taint:",required"`
}

func TestInvalidRequiredFieldErrorFromMap(t *testing.T) {
	s := map[string]string{}
	var d Struct3
	err := Inject(s, &d)
	terr, ok := err.(*FieldRequiredError)
	if !ok {
		t.Errorf("Expected FieldRequiredError, but got %#v", err)
	}
	if terr.FieldName != "Test2" {
		t.Errorf("Expected FieldRequiredError FieldName Test2, but got %#v", terr.FieldName)
	}
}

func TestInvalidRequiredFieldErrorFromStruct(t *testing.T) {
	s := struct{}{}
	var d Struct3
	err := Inject(s, &d)
	terr, ok := err.(*FieldRequiredError)
	if !ok {
		t.Errorf("Expected FieldRequiredError, but got %#v", err)
	}
	if terr.FieldName != "Test2" {
		t.Errorf("Expected FieldRequiredError FieldName Test2, but got %#v", terr.FieldName)
	}
}
