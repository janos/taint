// Copyright (c) 2015, Janoš Guljaš <janos@resenje.org>
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package taint // import "resenje.org/taint"

import (
	"errors"
	"reflect"
	"runtime"
	"strings"
)

var (
	// DefaultTagKey is a key for Go struct tags that this module will check.
	DefaultTagKey = "taint"
)

// Inject will inject fields of source object into destination object.
func Inject(src, dst interface{}) error {
	return InjectWithTag(src, dst, DefaultTagKey)
}

// InjectWithTag will inject fields of source object into destination object
// using a custom Go struct tag.
func InjectWithTag(src, dst interface{}, tagKey string) error {
	dstValue := reflect.ValueOf(dst)
	if dstValue.Kind() != reflect.Ptr || dstValue.IsNil() {
		return &InvalidInjectError{dstValue.Type()}
	}
	return inject(reflect.ValueOf(src), dstValue, tagKey)
}

func inject(srcValue, dstValue reflect.Value, tagKey string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			switch rt := r.(type) {
			case runtime.Error:
				panic(r)
			case error:
				err = rt
			case string:
				err = errors.New(rt)
			default:
				panic(r)
			}
		}
	}()

	dstValue = reflect.Indirect(dstValue)
	srcValue = reflect.Indirect(reflect.ValueOf(srcValue.Interface()))
	srcKind := srcValue.Kind()
	dstKind := dstValue.Kind()

	switch dstKind {
	case reflect.Slice:
		dstType := dstValue.Type()
		dstTypeElem := dstType.Elem()
		dstTypeElemKind := dstTypeElem.Kind()
		if srcKind == reflect.Slice {
			srcLen := srcValue.Len()
			dstValue.Set(reflect.MakeSlice(dstType, srcLen, srcValue.Cap()))
			for i := 0; i < srcLen; i++ {
				if err := inject(srcValue.Index(i), dstValue.Index(i), tagKey); err != nil {
					return err
				}
			}
			return nil
		}
		if dstTypeElemKind == reflect.Interface || srcKind == dstTypeElemKind {
			dstValue.Set(reflect.MakeSlice(dstType, 1, 1))
			return inject(srcValue, dstValue.Index(0), tagKey)
		}
		return &InvalidTypeError{
			TypeSrc: srcValue.Type(),
			TypeDst: dstType,
		}
	case reflect.Map:
		dstType := dstValue.Type()
		dstTypeElem := dstType.Elem()
		switch srcKind {
		case reflect.Map:
			dstTypeKey := dstType.Key()
			dstValue.Set(reflect.MakeMap(dstType))
			for _, srcKey := range srcValue.MapKeys() {
				dstKeyValue := reflect.New(dstTypeElem)
				if err := inject(srcValue.MapIndex(srcKey), dstKeyValue, tagKey); err != nil {
					return err
				}
				dstKey := reflect.New(dstTypeKey).Elem()
				dstKey.Set(reflect.ValueOf(srcKey.Interface()))
				dstValue.SetMapIndex(dstKey, reflect.Indirect(dstKeyValue))
			}
		case reflect.Struct:
			dstValue.Set(reflect.MakeMap(dstType))
			for i := 0; i < srcValue.NumField(); i++ {
				dstKeyValue := reflect.New(dstTypeElem)
				if err := inject(srcValue.Field(i), dstKeyValue, tagKey); err != nil {
					return err
				}
				srcFieldType := srcValue.Type().Field(i)
				keyName := keyNameFromTag(srcFieldType.Tag, tagKey)
				if keyName == "-" {
					continue
				}
				if keyName == "" {
					keyName = srcFieldType.Name
				}
				dstKey := reflect.New(reflect.TypeOf(keyName)).Elem()
				dstKey.SetString(keyName)
				dstValue.SetMapIndex(dstKey, reflect.Indirect(dstKeyValue))
			}
		default:
			return &InvalidTypeError{
				TypeSrc: srcValue.Type(),
				TypeDst: dstType,
			}
		}
	case reflect.Struct:
		switch srcKind {
		case reflect.Map:
			for i := 0; i < dstValue.NumField(); i++ {
				dstKeyValue := reflect.New(dstValue.Field(i).Type())
				dstFieldType := dstValue.Type().Field(i)
				keyName := keyNameFromTag(dstFieldType.Tag, tagKey)
				if keyName == "" {
					keyName = dstFieldType.Name
				}
				if keyName == "-" {
					continue
				}
				srcKey := reflect.New(reflect.TypeOf(keyName)).Elem()
				srcKey.SetString(keyName)
				srcMapValue := srcValue.MapIndex(srcKey)
				if !srcMapValue.IsValid() {
					if tagContains(dstFieldType.Tag, tagKey, "required") {
						return &FieldRequiredError{
							FieldName: keyName,
						}
					}
					continue
				}
				if err := inject(srcMapValue, dstKeyValue, tagKey); err != nil {
					return err
				}
				dstValue.Field(i).Set(reflect.Indirect(dstKeyValue))
			}
		case reflect.Struct:
			for i := 0; i < dstValue.NumField(); i++ {
				dstField := dstValue.Field(i)
				dstKeyValue := reflect.New(dstField.Type())
				dstFieldType := dstValue.Type().Field(i)
				fieldName := dstFieldType.Name
				tagName := keyNameFromTag(dstFieldType.Tag, tagKey)
				if tagName == "-" {
					continue
				}
				srcStructValue := srcValue.FieldByName(fieldName)
				if !srcStructValue.IsValid() {
					if tagName != "" {
						fieldName = tagName
					}
					srcStructValue = srcValue.FieldByName(fieldName)
					if !srcStructValue.IsValid() {
						srcStructValue = srcValue.FieldByName(strings.ToUpper(fieldName[:1]) + fieldName[1:])
					}
					if !srcStructValue.IsValid() {
						if tagContains(dstFieldType.Tag, tagKey, "required") {
							return &FieldRequiredError{
								FieldName: fieldName,
							}
						}
						continue
					}
				}
				srcStructValueTyped := srcStructValue
				if srcStructValueTyped.CanAddr() && dstField.Kind() == srcStructValueTyped.Addr().Kind() {
					srcStructValueTyped = srcStructValueTyped.Addr()
					srcStructValue = srcStructValue.Addr()
				}
				if !dstField.Type().AssignableTo(reflect.Indirect(srcStructValueTyped).Type()) {
					fieldValue := dstValue.FieldByName(fieldName)
					if fieldValue.IsValid() {
						srcStructValueTyped = reflect.New(fieldValue.Type())
						if err := inject(srcStructValue, srcStructValueTyped, tagKey); err != nil {
							return err
						}
					}
				}
				if err := inject(srcStructValueTyped, dstKeyValue, tagKey); err != nil {
					return err
				}
				if srcStructValueTyped.Type().AssignableTo(dstField.Type()) {
					dstField.Set(srcStructValueTyped)
				} else {
					dstField.Set(reflect.Indirect(srcStructValueTyped))
				}
			}
		default:
			return &InvalidTypeError{
				TypeSrc: srcValue.Type(),
				TypeDst: dstValue.Type(),
			}
		}
	case reflect.Array:
		dstTypeElem := dstValue.Type().Elem()
		if srcValue.Type().Elem().Kind() == dstTypeElem.Kind() {
			srcValueTyped := srcValue
			if !dstValue.Type().AssignableTo(srcValueTyped.Type()) {
				srcValueTyped = reflect.Indirect(reflect.New(dstValue.Type()))
				srcLen := srcValue.Len()
				for i := 0; i < srcLen; i++ {
					if err := inject(srcValue.Index(i), srcValueTyped.Index(i), tagKey); err != nil {
						return err
					}
				}
			}
			dstValue.Set(srcValueTyped)
			return
		}
		srcLen := srcValue.Len()
		dstValue.Set(reflect.New(reflect.ArrayOf(srcLen, dstTypeElem)).Elem())
		for i := 0; i < srcLen; i++ {
			if err := inject(srcValue.Index(i), dstValue.Index(i), tagKey); err != nil {
				return err
			}
		}
	default:
		if srcValue.CanAddr() && dstKind == srcValue.Addr().Kind() {
			srcValue = srcValue.Addr()
			srcKind = srcValue.Kind()
		}
		if dstKind != srcKind && dstKind != reflect.Interface {
			return &InvalidTypeError{
				TypeSrc: srcValue.Type(),
				TypeDst: dstValue.Type(),
			}
		}
		if srcValue.Type().AssignableTo(dstValue.Type()) {
			dstValue.Set(srcValue)
		} else {
			dstValue.Set(reflect.Indirect(srcValue))
		}
	}
	return nil
}

func keyNameFromTag(structTag reflect.StructTag, tagKey string) (keyName string) {
	if tag := structTag.Get(tagKey); tag != "" {
		if strings.Contains(tag, ",") {
			keyName = strings.Split(tag, ",")[0]
		} else {
			keyName = tag
		}
	}
	return keyName
}

func tagContains(structTag reflect.StructTag, tagKey, tagValue string) bool {
	if tag := structTag.Get(tagKey); tag != "" {
		l := strings.Split(tag, ",")
		if len(l) < 2 {
			return false
		}
		for _, e := range l[1:] {
			if e == tagValue {
				return true
			}
		}
	}
	return false
}
