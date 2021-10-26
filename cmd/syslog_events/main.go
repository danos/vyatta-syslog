// Copyright (c) 2021, AT&T Intellectual Property.
// All rights reserved.
//
//
// SPDX-License-Identifier: LGPL-2.1-only

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

type Msg struct {
	Timestamp string `json:"timestamp"`
	Host      string `json:"host"`
	Severity  int    `json:"severity"`
	Facility  int    `json:"facility"`
	Tag       string `json:"syslog-tag"`
	Source    string `json:"source"`
	Msg       string `json:"message"`
}

type Logs struct {
	Errors bool `json:"logerrors"`
	Output bool `json:"logoutput"`
}

type Info struct {
	Msg
	Logs
	Id        string `json:"event-id"`
	Handler   string `json:"event-handler"`
	Arguments string `json:"arguments"`
	User      string `json:"user"`
}

var (
	elog *log.Logger
	dlog *log.Logger
)

func init() {
	var err error
	errlog, err := syslog.New(syslog.LOG_ERR, "syslog_events")
	if err == nil {
		elog = log.New(errlog, "", 0)
	}
	if err != nil {
		elog = log.New(os.Stderr, "", 0)
	}
	dbglog, err := syslog.New(syslog.LOG_DEBUG, "syslog_events")
	if err == nil {
		dlog = log.New(dbglog, "", 0)
	}
	if err != nil {
		dlog = log.New(os.Stdout, "", 0)
	}
}

func parseUint32Slice(g []string) []uint32 {
	r := make([]uint32, 0)

	for _, v := range g {
		n, _ := strconv.ParseUint(v, 10, 32)
		r = append(r, uint32(n))
	}
	return r
}

func executeHandler(info Info, syslogMsg []byte) {
	var ster bytes.Buffer
	stdin := bytes.NewReader(syslogMsg)
	stderr := bufio.NewWriter(&ster)

	u, err := user.Lookup(info.User)
	if err != nil {
		elog.Printf("User %s error %s\n", info.User, err)
		return
	}

	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	grpIds, _ := u.GroupIds()

	cmd := exec.Command("/opt/vyatta/sbin/lu", "--user", info.User, "/config/scripts/vyatta-syslog-events/"+info.Handler)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uint32(uid),
			Gid:    uint32(gid),
			Groups: parseUint32Slice(grpIds),
		},
	}

	id := "SYSLOG_EVENT_ARGS=" + info.Arguments
	cmd.Env = append(os.Environ(), id)

	cmd.Stdin = stdin
	cmd.Stderr = stderr

	out, err := cmd.Output()

	if info.Logs.Errors && (err != nil || ster.Len() != 0) {
		if err != nil {
			elog.Printf("Event script \"%s\" error: %s\n", info.Handler, err)
			return
		}
		elog.Printf("Event script \"%s\" error: %s\n", info.Handler, ster.String())
	}

	if info.Logs.Output && len(out) > 0 {
		dlog.Printf("Event script \"%s\" output: %s\n", info.Handler, string(out))
	}
}

func process(s string) {
	var info Info

	err := json.Unmarshal([]byte(s), &info)
	if err != nil {
		elog.Printf("Error: %s\n", err)
		return
	}

	if info.Handler == "" {
		return
	}

	syslogMsg, err := json.Marshal(info.Msg)
	if err != nil {
		elog.Printf("Error: %s\n", err)
		return
	}

	if info.User == "" {
		info.User = "root"
	}

	executeHandler(info, syslogMsg)
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		input := scanner.Text()
		process(input)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}
}
