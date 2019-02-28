package main

type Type interface{}

type Value Type

type List		struct {
	contents	map[string]Value
}

func	(l* List)Get(key string) (Value, bool) {

	val, ok := l.contents[key]
	return val, ok
}

func	(l* List)Del(key string) {

	delete(l.contents, key)
}

func	(l* List)Add(key string, val Value) {

	if l.contents == nil {
		l.contents = make(map[string]Value)
	}
	l.contents[key] = val
}