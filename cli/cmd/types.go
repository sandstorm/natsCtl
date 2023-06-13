package cmd

import "fmt"

type OperatorName string
type AccountName string
type AccountDescription string
type RoleName string
type UserName string

type Key interface {
	Key() string
}
type ScopedSigningKey string

func (k ScopedSigningKey) Key() string {
	return string(k)
}

type AccountKey string

func (k AccountKey) Key() string {
	return string(k)
}

type UserKey string

func (k UserKey) Key() string {
	return string(k)
}

func InboxPrefix(pubKey string) string {
	return fmt.Sprintf("_PRIV_INBOX.%s", pubKey)
}

type AccountSigningKey string

func (k AccountSigningKey) Key() string {
	return string(k)
}

type OperatorKey string

func (k OperatorKey) Key() string {
	return string(k)
}

type OperatorSigningKey string

func (k OperatorSigningKey) Key() string {
	return string(k)
}
