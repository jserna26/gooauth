package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func main() {
	//Validate whether path to certificate and key passed os.Args
	StartSever()
}

//GoogleContact struct
type GoogleContact struct {
	User []struct {
		Name  string `xml:"name" json:"Username"`
		Email string `xml:"email" json:"UserEmail"`
	} `xml:"author" json:"User"`
	ContactDetails []struct {
		Name        string `xml:"title" json:"Name"`
		Email       string `xml:"email" json:"Email"`
		LastUpdated string `xml:"updated" json:"last_updated"`
		Phone       string `xml:"gd:phoneNumber" json:"Phone"`
	} `xml:"entry" json:"Contacts"`
}

type config struct {
	CertPath string `json:"certPath"`
	Oauth    map[string]struct {
		ClientID     string `json:"clientid"`
		ClientSecret string `json:"clientsecret"`
	}
}

//Func readConfig - Reads config file and returns config params for use.
func readConfig() (certPath string, clientID string, clientSecret string) {
	file, err := ioutil.ReadFile("../../config.json")
	if err != nil {
		log.Println(err)
	}
	data := config{}
	json.Unmarshal(file, &data)
	certPath = data.CertPath
	clientID = data.Oauth["Google"].ClientID
	clientSecret = data.Oauth["Google"].ClientSecret
	return certPath, clientID, clientSecret
}

//GetGoogleContacts func-
func GetGoogleContacts(w http.ResponseWriter, r *http.Request) {
	state, config := getAuthConfig()
	//Return provider auth consent page based on defined scopes.
	url := config.AuthCodeURL(state)
	//fmt.Println(url)
	//Redirect the user to the provider consent page
	http.Redirect(w, r, url, http.StatusFound)
}

//getAuthConfig func
func getAuthConfig() (State string, Config *oauth2.Config) {
	// TODO: Generate random string /hash
	state := uuid.NewV4().String()

	_, clientID, clientSecret := readConfig()
	//Create oauth config object with auth details
	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "https://localhost:443/auth",
		//Response_type: "code",
		Scopes: []string{
			"https://www.googleapis.com/auth/contacts.readonly",
		},
		Endpoint: google.Endpoint,
	}
	return state, config
}

//AuthenticateClient func
func AuthenticateClient(w http.ResponseWriter, r *http.Request) {

	clientState, config := getAuthConfig()
	authcode := r.URL.Query().Get("code")
	respState := r.URL.Query().Get("state")
	if clientState != respState {
		fmt.Fprintf(w, "The state key provided - %s as part of the authorization process does not match the state key returned - %s. This could be as a result of a cross site forgery attempt!", clientState, respState)
		os.Exit(2)
	}

	token, err := config.Exchange(nil, authcode)
	if err != nil {
		log.Println(err)
	}

	b := new(bytes.Buffer)

	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://www.google.com/m8/feeds/contacts/default/full", b)
	if err != nil {
		log.Println(err)
	}
	i := "Bearer " + token.AccessToken

	//Set request headers
	req.Header.Add("Authorization", i)
	//Set Url params
	req.URL.Query().Add("GData-Version", "3.0")
	req.URL.Query().Add("max-results", "50")
	//	req.Header.Add("Accept", "application/json")
	//fmt.Println(req.Header)
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
	}
	defer resp.Body.Close()

	bits, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	//json.NewDecoder(bytes.NewReader(bits)).Decode(resp.Body)
	data := &GoogleContact{}

	err = xml.Unmarshal(bits, data)
	if err != nil {
		fmt.Println(err)
	}

	result, err := json.MarshalIndent(data, "", " ")

	if err != nil {
		log.Println(err)
	}
	//json.NewEncoder(bytes.NewReader(bits)).Encode(resp.Body)
	//w.Write(bits)
	fmt.Fprintf(w, "List of google contacts for: %s", result)

	if err != nil {
		log.Println(err)
	}
	//fmt.Println(resp)
	//	fmt.Println(token)
}

//StartSever func
func StartSever() {

	/*
		if len(os.Args) < 2 {
			log.Println("Must pass directory path to the certificate and key as an argument when running the exe.")
			os.Exit(2)
		}*/

	path, _, _ := readConfig()

	//Assign cert&key absolute paths to variables
	var cert = path + "\\cert.pem"
	var sslkey = path + "\\key.pem"

	//Create new gorilla mux router and define route handler based on the url path defined.
	r := mux.NewRouter()
	r.HandleFunc("/getcontacts", GetGoogleContacts).Methods("GET")
	r.HandleFunc("/auth", AuthenticateClient).Methods("GET")

	//Create new CertPool instance and append PEM cert
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(cert))
	tlsConf := &tls.Config{
		RootCAs:            roots,
		InsecureSkipVerify: true,
	}

	//Configure http server struct
	server := http.Server{
		Addr:      ":443",
		Handler:   r,
		TLSConfig: tlsConf,
	}

	log.Printf("Server Listening on port %s", server.Addr)
	err := server.ListenAndServeTLS(cert, sslkey)
	if err != nil {
		log.Fatal(err)
	}
}
