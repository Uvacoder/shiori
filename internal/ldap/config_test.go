package ldap

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    Config
		wantErr bool
	}{
		{
			name:    "validate version error",
			value:   "version = 0",
			want:    Config{},
			wantErr: true,
		}, {
			name:    "parse error",
			value:   "version = 1",
			want:    Config{},
			wantErr: true,
		}, {
			name: "parse ok and validate ok",
			value: `version = 1
				host = "ldap.example.org"
				port = 389

				[tls]
				enabled = true
				SkipCertVerification = true

				[bind]
				userDN = "cn=svcuser,ou=users,dc=example,dc=org"
				password = "PASSWORD"

				[search]
				base = "ou=users,dc=example,dc=org"
				filter = "(&(memberOf={{.Group}})(|(mail={{.Login}})(sAMAccountName={{.Login}})))"
				ownerGroupDN = "cn=shiori_owners,ou=group,dc=example,dc=org"
				visitorGroupDN = "cn=shiori_visitors,ou=group,dc=example,dc=org"
				loginField = "sAMAccountName"`,
			want: Config{
				Version: 1,
				Host:    "ldap.example.org",
				Port:    389,
				TLS: TLSConfig{
					Enabled:              true,
					SkipCertVerification: true,
				},
				Bind: BindConfig{
					UserDN:   "cn=svcuser,ou=users,dc=example,dc=org",
					Password: "PASSWORD",
				},
				Search: SearchConfig{
					Base:           "ou=users,dc=example,dc=org",
					Filter:         "(&(memberOf={{.Group}})(|(mail={{.Login}})(sAMAccountName={{.Login}})))",
					OwnerGroupDN:   "cn=shiori_owners,ou=group,dc=example,dc=org",
					VisitorGroupDN: "cn=shiori_visitors,ou=group,dc=example,dc=org",
					LoginField:     "sAMAccountName",
				},
			},
			wantErr: false,
		}, {
			name: "parse failed not enough fields",
			value: `version = 1	
				host = "ldap.example.org"`,
			want:    Config{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.value)
			got, err := ParseConfig(r)

			if err != nil {
				if !tt.wantErr {
					t.Errorf("ParseConfig() got error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseConfig() = %v, want %v", got, tt.want)
				return
			}
		})
	}
}
