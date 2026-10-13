package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"firewall-ui/internal/auth"
	"firewall-ui/internal/firewall"
	"firewall-ui/internal/ipset"
	"firewall-ui/internal/storage"
)

type testBackend struct{}

func (testBackend) Load() (*firewall.Ruleset, error) {
	return &firewall.Ruleset{Policies: map[string]string{}}, nil
}
func (testBackend) Validate(*firewall.Ruleset) error  { return nil }
func (testBackend) Apply(*firewall.Ruleset) error     { return nil }
func (testBackend) Backup() (*firewall.Backup, error) { return &firewall.Backup{}, nil }
func (testBackend) Restore(*firewall.Backup) error    { return nil }

func TestAliasesRouteExists(t *testing.T) {
	store, err := storage.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	authService := &auth.Service{Store: store}
	if err = authService.Bootstrap("admin", "strong-password"); err != nil {
		t.Fatal(err)
	}
	token, _, err := authService.Login("admin", "strong-password", "test")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Auth: authService, Store: store, Draft: firewall.NewDraftService(testBackend{}, time.Minute), IPSet: ipset.New()}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/aliases", nil)
	request.AddCookie(&http.Cookie{Name: "fwui_session", Value: token})
	response := httptest.NewRecorder()
	WithAliasRoutes(server, server.Handler()).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}
