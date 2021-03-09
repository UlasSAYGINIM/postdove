package maildb

/*
 * Copyright (C) 2020, Jim Lieb <lieb@sea-troll.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * -------------
 */

import (
	//"database/sql"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	//"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3" // do I really need this here?
)

// doInsertDomain
func doInsertDomain(mdb *MailDB, name string) (d *Domain, err error) {
	if err = mdb.begin(); err != nil {
		return
	}
	defer mdb.end(err == nil)

	d, err = mdb.InsertDomain(name)
	return
}

// TestDomain
func TestDomain(t *testing.T) {
	var (
		err error
		mdb *MailDB
		dir string
		d   *Domain
	)

	fmt.Printf("Domain Test\n")

	dir, err = ioutil.TempDir("", "TestDBLoad-*")
	defer os.RemoveAll(dir)
	mdb, err = makeTestDB(filepath.Join(dir, "test.db"), "../schema.sql")
	if err != nil {
		t.Errorf("Database load failed, %s", err)
		return
	}
	defer mdb.Close()

	// Try to insert a domain
	d, err = doInsertDomain(mdb, "foo")
	if err != nil {
		t.Errorf("Insert foo: %s", err)
		return // no need to go further this early
	} else {
		if d.String() != "foo" {
			t.Errorf("Insert foo: bad String(), %s", d.String())
		}
		// NOTE: this will fail if you change schema defaults...
		if d.dump() != "id=1, name=foo, class=0, transport=<NULL>, access=<NULL>, vuid=<NULL>, vgid=<NULL>, rclass=DEFAULT." {
			t.Errorf("Insert foo: bad dump(), %s", d.dump())
		}
	}

	// Try some bad args...
	d, err = doInsertDomain(mdb, "")
	if err == nil {
		t.Errorf("Insert \"\" should have failed")
	} else if err != ErrMdbBadName {
		t.Errorf("Insert of \"\": %s", err)
	}
	d, err = doInsertDomain(mdb, ";bogus")
	if err == nil {
		t.Errorf("Insert \";bogus\" should have failed")
	} else if err != ErrMdbBadName {
		t.Errorf("Insert of \";bogus\": %s", err)
	}

	// Lookup should agree with Insert...
	d, err = mdb.LookupDomain("foo")
	if err != nil {
		t.Errorf("Lookup foo: %s", err)
	} else {
		if d.String() != "foo" {
			t.Errorf("Lookup foo: bad String(), %s", d.String())
		}
		// NOTE: this will fail if you change schema defaults...
		if d.dump() != "id=1, name=foo, class=0, transport=<NULL>, access=<NULL>, vuid=<NULL>, vgid=<NULL>, rclass=DEFAULT." {
			t.Errorf("Lookup foo: bad dump(), %s", d.dump())
		}
	}

	// Lookup something not there
	d, err = mdb.LookupDomain("baz")
	if err == nil {
		t.Errorf("Lookup baz should have failed: got %s", d.dump())
	} else if err != ErrMdbDomainNotFound {
		t.Errorf("Lookup baz: %s", err)
	}

	// Delete stuff
	err = mdb.DeleteDomain("baz")
	if err == nil {
		t.Errorf("Delete baz should have failed")
	}
	err = mdb.DeleteDomain("foo")
	if err != nil {
		t.Errorf("Delete foo: %s", err)
	}
}
