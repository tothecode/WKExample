using System;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Collections.Specialized;
using WK.Integration;

namespace LoginGovPlExample
{
    /// <summary>
    /// Przykładowa klasa demonstrująca wykorzystanie integracji z login.gov.pl
    /// </summary>
    public class LoginGovPlExample
    {
        private const string Issuer = "https://mojausluga.gov.pl";
        private const string AssertionConsumerServiceUrl = "https://mojausluga.gov.pl/acs";
        private const string ProviderName = "MojaUsługa";
        private const bool IsPublicEntity = true; // dla podmiotu publicznego
        private const string AuthnLevel = "substantial"; // domyślny poziom uwierzytelnienia
        private const string Environment = "int"; // środowisko integracyjne
        
        private readonly LoginGovPlClient _client;
        
        public LoginGovPlExample()
        {
            // Wczytywanie certyfikatów z magazynu certyfikatów
            X509Certificate2 signCertificate = LoadCertificate("CertyfikatDoPodpisu");
            X509Certificate2 encryptionCertificate = LoadCertificate("CertyfikatDoSzyfrowania");
            
            // Inicjalizacja klienta
            _client = new LoginGovPlClient(
                signCertificate,
                encryptionCertificate,
                Issuer,
                AssertionConsumerServiceUrl,
                ProviderName,
                IsPublicEntity,
                AuthnLevel,
                Environment
            );
        }
        
        /// <summary>
        /// Metoda rozpoczynająca proces uwierzytelnienia
        /// </summary>
        /// <returns>Formularz HTML z żądaniem uwierzytelnienia</returns>
        public string StartAuthentication()
        {
            // Generowanie żądania uwierzytelnienia
            string requestId = $"ID-{Guid.NewGuid()}";
            string authnRequest = _client.GenerateAuthnRequest(requestId);
            
            // Zwrócenie formularza HTML z żądaniem uwierzytelnienia
            return authnRequest;
        }
        
        /// <summary>
        /// Metoda rozpoczynająca proces uwierzytelnienia transgranicznego
        /// </summary>
        /// <returns>Formularz HTML z żądaniem uwierzytelnienia transgranicznego</returns>
        public string StartForeignAuthentication()
        {
            // Generowanie żądania uwierzytelnienia z włączonym uwierzytelnianiem transgranicznym
            string requestId = $"ID-{Guid.NewGuid()}";
            string authnRequest = _client.GenerateAuthnRequest(requestId, true);
            
            // Zwrócenie formularza HTML z żądaniem uwierzytelnienia
            return authnRequest;
        }
        
        /// <summary>
        /// Metoda przetwarzająca artefakt SAML zwrócony przez login.gov.pl
        /// </summary>
        /// <param name="artifact">Artefakt SAML</param>
        /// <returns>Informacje o uwierzytelnionym użytkowniku</returns>
        public SamlAssertion ProcessArtifact(string artifact)
        {
            // Wywołanie metody przetwarzającej artefakt
            SamlAssertion assertion = _client.ProcessArtifactResponse(artifact);
            
            // Zwrócenie informacji o użytkowniku
            return assertion;
        }
        
        /// <summary>
        /// Metoda wylogowująca użytkownika
        /// </summary>
        /// <param name="nameId">Identyfikator użytkownika</param>
        /// <param name="sessionIndex">Indeks sesji</param>
        /// <returns>Status wylogowania</returns>
        public SamlLogoutStatus Logout(string nameId, string sessionIndex)
        {
            // Wywołanie metody wylogowującej
            return _client.Logout(nameId, sessionIndex);
        }
        
        /// <summary>
        /// Metoda pomocnicza do wczytywania certyfikatu z magazynu certyfikatów
        /// </summary>
        /// <param name="thumbprint">Odcisk palca certyfikatu</param>
        /// <returns>Certyfikat</returns>
        private X509Certificate2 LoadCertificate(string thumbprint)
        {
            // W rzeczywistej implementacji certyfikaty mogą być wczytywane z magazynu certyfikatów
            // lub z plików
            
            // Przykład wczytywania z magazynu certyfikatów
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certs = store.Certificates.Find(
                    X509FindType.FindByThumbprint, 
                    thumbprint, 
                    false
                );
                
                if (certs.Count == 0)
                {
                    throw new ApplicationException($"Nie znaleziono certyfikatu o odcisku palca: {thumbprint}");
                }
                
                return certs[0];
            }
            finally
            {
                store.Close();
            }
        }
    }
    
    /// <summary>
    /// Przykładowa klasa kontrolera ASP.NET MVC demonstrująca integrację z login.gov.pl
    /// </summary>
    public class LoginGovPlController
    {
        private readonly LoginGovPlExample _loginGovPlExample;
        
        public LoginGovPlController()
        {
            _loginGovPlExample = new LoginGovPlExample();
        }
        
        /// <summary>
        /// Akcja rozpoczynająca proces uwierzytelnienia
        /// </summary>
        public string Login()
        {
            // Wygenerowanie żądania uwierzytelnienia
            string authnRequest = _loginGovPlExample.StartAuthentication();
            
            // Zwrócenie formularza HTML z żądaniem uwierzytelnienia
            return authnRequest;
        }
        
        /// <summary>
        /// Akcja rozpoczynająca proces uwierzytelnienia transgranicznego
        /// </summary>
        public string LoginForeign()
        {
            // Wygenerowanie żądania uwierzytelnienia transgranicznego
            string authnRequest = _loginGovPlExample.StartForeignAuthentication();
            
            // Zwrócenie formularza HTML z żądaniem uwierzytelnienia
            return authnRequest;
        }
        
        /// <summary>
        /// Akcja przetwarzająca artefakt SAML zwrócony przez login.gov.pl
        /// </summary>
        public string AssertionConsumerService(string SAMLart)
        {
            try
            {
                // Przetworzenie artefaktu SAML
                SamlAssertion assertion = _loginGovPlExample.ProcessArtifact(SAMLart);
                
                // Użytkownik został pomyślnie uwierzytelniony
                // Tutaj można utworzyć sesję, zapisać dane użytkownika itp.
                
                // Utworzenie ciasteczka sesji
                HttpCookie cookie = new HttpCookie("SessionIndex", assertion.SessionIndex);
                HttpContext.Current.Response.Cookies.Add(cookie);
                
                // Zapisanie NameID w sesji
                HttpContext.Current.Session["NameID"] = assertion.NameID;
                
                // Przekierowanie do strony głównej aplikacji
                HttpContext.Current.Response.Redirect("/Home");
                
                return "Użytkownik został pomyślnie uwierzytelniony.";
            }
            catch (Exception ex)
            {
                // Obsługa błędów uwierzytelnienia
                return $"Błąd uwierzytelnienia: {ex.Message}";
            }
        }
        
        /// <summary>
        /// Akcja wylogowująca użytkownika
        /// </summary>
        public string Logout()
        {
            try
            {
                // Pobranie NameID i SessionIndex z sesji
                string nameId = HttpContext.Current.Session["NameID"] as string;
                string sessionIndex = HttpContext.Current.Request.Cookies["SessionIndex"]?.Value;
                
                if (string.IsNullOrEmpty(nameId) || string.IsNullOrEmpty(sessionIndex))
                {
                    return "Brak danych sesji do wylogowania.";
                }
                
                // Wywołanie metody wylogowującej
                SamlLogoutStatus status = _loginGovPlExample.Logout(nameId, sessionIndex);
                
                // Usunięcie danych sesji
                HttpContext.Current.Session.Remove("NameID");
                HttpContext.Current.Response.Cookies["SessionIndex"].Expires = DateTime.Now.AddDays(-1);
                
                // Przekierowanie do strony logowania
                HttpContext.Current.Response.Redirect("/Login");
                
                return $"Użytkownik został wylogowany. Status: {status}";
            }
            catch (Exception ex)
            {
                // Obsługa błędów wylogowania
                return $"Błąd wylogowania: {ex.Message}";
            }
        }
    }
}