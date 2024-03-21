// Copyright (c) 2015, Janoš Guljaš <janos@resenje.org>
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package taint

import (
	"math/big"
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

func TestInjectStructUnassignableTypeWithSlice(t *testing.T) {
	type KV struct {
		Key   string
		Value string
	}

	type Record struct {
		ID      uint64
		Map     []KV
		Comment string
	}

	s := struct {
		ID  uint64
		Map []struct {
			Key   string
			Value string
		}
		Comment string
	}{
		ID: 3,
		Map: []struct {
			Key   string
			Value string
		}{
			{"k1", "v1"},
			{"k2", "v2"},
		},
		Comment: "Hey",
	}
	var d Record
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}

	if d.ID != s.ID {
		t.Errorf("got %v, want %v", d.ID, s.ID)
	}
	if d.Map[0] != s.Map[0] {
		t.Errorf("got %v, want %v", d.Map[0], s.Map[0])
	}
	if d.Map[1] != s.Map[1] {
		t.Errorf("got %v, want %v", d.Map[1], s.Map[1])
	}
	if d.Comment != s.Comment {
		t.Errorf("got %v, want %v", d.Comment, s.Comment)
	}
}

func TestInjectStructUnassignableTypeWithArray(t *testing.T) {

	type KV struct {
		Key   string
		Value string
	}

	type Record struct {
		ID      uint64
		Map     [2]KV
		Comment string
	}

	s := struct {
		ID  uint64
		Map [2]struct {
			Key   string
			Value string
		}
		Comment string
	}{
		ID: 3,
		Map: [2]struct {
			Key   string
			Value string
		}{
			{"k1", "v1"},
			{"k2", "v2"},
		},
		Comment: "Hey",
	}
	var d Record
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}

	if d.ID != s.ID {
		t.Errorf("got %v, want %v", d.ID, s.ID)
	}
	if d.Map[0] != s.Map[0] {
		t.Errorf("got %v, want %v", d.Map[0], s.Map[0])
	}
	if d.Map[1] != s.Map[1] {
		t.Errorf("got %v, want %v", d.Map[1], s.Map[1])
	}
	if d.Comment != s.Comment {
		t.Errorf("got %v, want %v", d.Comment, s.Comment)
	}
}

func TestInjectStructUnassignableTypeWithStructField(t *testing.T) {

	type KV struct {
		Key   string
		Value string
	}

	type Record struct {
		ID      uint64
		Map     KV
		Comment string
	}

	s := struct {
		ID  uint64
		Map struct {
			Key   string
			Value string
		}
		Comment string
	}{
		ID: 3,
		Map: struct {
			Key   string
			Value string
		}{"k1", "v1"},
		Comment: "Hey",
	}
	var d Record
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}

	if d.ID != s.ID {
		t.Errorf("got %v, want %v", d.ID, s.ID)
	}
	if d.Map != s.Map {
		t.Errorf("got %v, want %v", d.Map, s.Map)
	}
	if d.Comment != s.Comment {
		t.Errorf("got %v, want %v", d.Comment, s.Comment)
	}
}

func TestInjectStructUnassignableTypeWithMap(t *testing.T) {

	type KV struct {
		Key   string
		Value string
	}

	type Record struct {
		ID      uint64
		Map     map[KV]KV
		Comment string
	}

	s := struct {
		ID  uint64
		Map map[struct {
			Key   string
			Value string
		}]struct {
			Key   string
			Value string
		}
		Comment string
	}{
		ID: 3,
		Map: map[struct {
			Key   string
			Value string
		}]struct {
			Key   string
			Value string
		}{
			{"k1", "v1"}: {"k2", "v2"},
			{"k3", "v3"}: {"k4", "v4"},
		},
		Comment: "Hey",
	}
	var d Record
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}

	if d.ID != s.ID {
		t.Errorf("got %v, want %v", d.ID, s.ID)
	}
	k1 := KV{"k1", "v1"}
	if d.Map[k1] != s.Map[k1] {
		t.Errorf("got %v, want %v", d.Map[k1], s.Map[k1])
	}
	k2 := KV{"k3", "v3"}
	if d.Map[k2] != s.Map[k2] {
		t.Errorf("got %v, want %v", d.Map[k2], s.Map[k2])
	}
	if d.Comment != s.Comment {
		t.Errorf("got %v, want %v", d.Comment, s.Comment)
	}
}

func TestInjectStruct1ToStruct2BtTagName(t *testing.T) {
	s := struct {
		SomethingStrange string
		Hey              string
		Doit             string `taint:"Do it"`
		Field4           string `taint:"-"`
		Field5           string
	}{
		SomethingStrange: "test1",
		Hey:              "test2",
		Doit:             "test3",
		Field4:           "test4",
		Field5:           "test5",
	}
	expected := struct {
		Field1 string `taint:"somethingStrange"`
		Field2 string `taint:"Hey"`
		Field3 string `taint:"Do it"`
		Field4 string `taint:"-"`
		Field5 string
	}{
		Field1: "test1",
		Field2: "test2",
		Field3: "",
		Field4: "",
		Field5: "test5",
	}

	var d struct {
		Field1 string `taint:"somethingStrange"`
		Field2 string `taint:"Hey"`
		Field3 string `taint:"Do it"`
		Field4 string `taint:"-"`
		Field5 string
	}
	if err := Inject(s, &d); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, expected) {
		t.Errorf("%T destination %#v is not set to %#v", d, d, expected)
	}
}

func TestInjectPointer(t *testing.T) {
	s := big.NewInt(42)
	var d *big.Int
	expected := big.NewInt(42)
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
