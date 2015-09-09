package taint // import "resenje.org/taint"

import "reflect"

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

type FieldRequiredError struct {
	FieldName string
}

func (e *FieldRequiredError) Error() string {
	return "taint: inject required field " + e.FieldName
}

type InvalidTypeError struct {
	TypeSrc reflect.Type
	TypeDst reflect.Type
}

func (e *InvalidTypeError) Error() string {
	return "taint: inject source type " + e.TypeSrc.String() + " != destination type " + e.TypeDst.String()
}
