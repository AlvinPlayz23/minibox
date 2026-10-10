//go:build linux

package compose

import "testing"

func TestParseCompose(t *testing.T) {
	p, err := Parse([]byte(`
services:
  web:
    image: alpine
    command: sh -c 'echo hi'
    ports:
      - "8080:80"
    environment:
      - A=1
      - B=2
    volumes:
      - data:/data
    network: bridge
    restart: always
    working_dir: /srv
    user: "1000"
    hostname: web
  db:
    image: "postgres:16"
    command:
      - postgres
      - -c
      - config_file=/etc/x
    environment:
      POSTGRES_PASSWORD: secret
      PGDATA: /data
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Services) != 2 {
		t.Fatalf("%v", p.Services)
	}
	web := p.Services[0]
	if web.Image != "alpine" || len(web.Ports) != 1 || len(web.Environment) != 2 || web.Workdir != "/srv" || web.User != "1000" {
		t.Errorf("%+v", web)
	}
	if len(web.Command) != 3 || web.Command[0] != "sh" {
		t.Errorf("command: %q", web.Command)
	}
	db := p.Services[1]
	if len(db.Command) != 3 || db.Environment[0] != "POSTGRES_PASSWORD=secret" {
		t.Errorf("%+v", db)
	}
}

func TestParseComposeErrors(t *testing.T) {
	for _, doc := range []string{
		"",
		"services:\n",
		"web:\n  image: x\n",
		"services:\n  web:\n",
		"services:\n  web:\n    image: x\n    bogus: y\n",
		"services:\n  web:\n    command: x\n",
		"services:\n top:\n    image: x\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("accepted:\n%s", doc)
		}
	}
}
