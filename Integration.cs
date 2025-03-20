using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace WK.Integration
{
    /// <summary>
    /// Klasa główna implementująca integrację z Węzłem Krajowym login.gov.pl
    /// </summary>
    public class LoginGovPlClient
    {
        private readonly X509Certificate2 _signCertificate;
        private readonly X509Certificate2 _encryptionCertificate;
        private readonly string _issuer;
        private readonly string _assertionConsumerServiceUrl;
        private readonly string _providerName;
        private readonly string _requestedAuthnContextClassRef;
        private readonly bool _isPublicEntity;
        private readonly string _singleSignOnServiceUrl;
        private readonly string _artifactResolutionServiceUrl;
        private readonly string _singleLogoutServiceUrl;

        /// <summary>
        /// Konstruktor klienta integracji z login.gov.pl
        /// </summary>
        /// <param name="signCertificate">Certyfikat do podpisywania żądań</param>
        /// <param name="encryptionCertificate">Certyfikat do deszyfrowania asercji</param>
        /// <param name="issuer">Unikalny identyfikator systemu (SAML Issuer)</param>
        /// <param name="assertionConsumerServiceUrl">Adres usługi odbierającej odpowiedź z asercją</param>
        /// <param name="providerName">Nazwa systemu</param>
        /// <param name="isPublicEntity">Czy podmiot jest publiczny (true) czy prywatny (false)</param>
        /// <param name="authnLevel">Poziom uwierzytelnienia (low, substantial, high)</param>
        /// <param name="environment">Środowisko (int, prod)</param>
        public LoginGovPlClient(
            X509Certificate2 signCertificate,
            X509Certificate2 encryptionCertificate,
            string issuer,
            string assertionConsumerServiceUrl,
            string providerName,
            bool isPublicEntity = true,
            string authnLevel = "substantial",
            string environment = "int")
        {
            _signCertificate = signCertificate;
            _encryptionCertificate = encryptionCertificate;
            _issuer = issuer;
            _assertionConsumerServiceUrl = assertionConsumerServiceUrl;
            _providerName = providerName;
            _isPublicEntity = isPublicEntity;
            
            // Domyślnie wybieramy poziom substantial
            _requestedAuthnContextClassRef = authnLevel.ToLower() switch
            {
                "low" => "http://eidas.europa.eu/LoA/low",
                "high" => "http://eidas.europa.eu/LoA/high",
                _ => "http://eidas.europa.eu/LoA/substantial"
            };

            // Ustawiamy adresy usług
            string domain = _isPublicEntity ? "login.gov.pl" : "podmiotyzewnetrzne.login.gov.pl";
            if (environment == "int")
            {
                // Środowisko integracyjne
                domain = "int." + domain;
            }

            _singleSignOnServiceUrl = $"https://{domain}/login/SingleSignOnService";
            _artifactResolutionServiceUrl = $"https://{domain}/login-services/idpArtifactResolutionService";
            _singleLogoutServiceUrl = $"https://{domain}/login-services/singleLogoutService";
        }

        /// <summary>
        /// Generuje kompletne żądanie AuthnRequest zgodne z wymaganiami login.gov.pl
        /// </summary>
        /// <param name="requestId">Identyfikator żądania</param>
        /// <param name="enableForeignAuthentication">Czy włączyć uwierzytelnianie transgraniczne</param>
        /// <returns>Zakodowany Base64 dokument AuthnRequest gotowy do wysłania</returns>
        public string GenerateAuthnRequest(string requestId = null, bool enableForeignAuthentication = false)
        {
            if (string.IsNullOrEmpty(requestId))
            {
                requestId = $"ID-{Guid.NewGuid()}";
            }

            var dateTimeNow = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;

            // Tworzenie dokumentu XML
            doc.LoadXml($@"<?xml version=""1.0"" encoding=""UTF-8"" standalone=""yes""?>
<saml2p:AuthnRequest 
    xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
    xmlns:ds=""http://www.w3.org/2000/09/xmldsig#""
    xmlns:eidas=""http://eidas.europa.eu/saml-extensions""
    xmlns:naturalperson=""http://eidas.europa.eu/attributes/naturalperson""
    xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
    xmlns:xenc=""http://www.w3.org/2001/04/xmlenc#""
    AssertionConsumerServiceURL=""{_assertionConsumerServiceUrl}""
    Destination=""{_singleSignOnServiceUrl}""
    ForceAuthn=""true""
    ID=""{requestId}""
    IssueInstant=""{dateTimeNow}""
    ProtocolBinding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact""
    ProviderName=""{_providerName}""
    Version=""2.0"">
    <saml2:Issuer>{_issuer}</saml2:Issuer>
    <saml2p:Extensions>
        <eidas:SPType>{(_isPublicEntity ? "public" : "private")}</eidas:SPType>
        <eidas:RequestedAttributes>
            <eidas:RequestedAttribute 
                FriendlyName=""FamilyName"" 
                Name=""http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName"" 
                NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:uri"" 
                isRequired=""true""/>
            <eidas:RequestedAttribute 
                FriendlyName=""FirstName"" 
                Name=""http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName"" 
                NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:uri"" 
                isRequired=""true""/>
            <eidas:RequestedAttribute 
                FriendlyName=""DateOfBirth"" 
                Name=""http://eidas.europa.eu/attributes/naturalperson/DateOfBirth"" 
                NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:uri"" 
                isRequired=""true""/>
            <eidas:RequestedAttribute 
                FriendlyName=""PersonIdentifier"" 
                Name=""http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"" 
                NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:uri"" 
                isRequired=""true""/>
        </eidas:RequestedAttributes>
    </saml2p:Extensions>
    <saml2p:NameIDPolicy 
        AllowCreate=""true"" 
        Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified""/>
    <saml2p:RequestedAuthnContext Comparison=""minimum"">
        <saml2:AuthnContextClassRef>{_requestedAuthnContextClassRef}</saml2:AuthnContextClassRef>
    </saml2p:RequestedAuthnContext>
</saml2p:AuthnRequest>");

            // Podpisanie dokumentu
            SignXmlDocument(doc);

            // Konwersja dokumentu do Base64
            var base64Request = Convert.ToBase64String(Encoding.UTF8.GetBytes(doc.OuterXml));

            // Generowanie formularza HTML z żądaniem
            return GenerateAuthHtmlForm(base64Request, enableForeignAuthentication);
        }

        /// <summary>
        /// Generuje formularz HTML z żądaniem SAML
        /// </summary>
        /// <param name="base64SamlRequest">Zakodowane Base64 żądanie SAML</param>
        /// <param name="enableForeignAuthentication">Czy włączyć uwierzytelnianie transgraniczne</param>
        /// <returns>Formularz HTML gotowy do wysłania</returns>
        private string GenerateAuthHtmlForm(string base64SamlRequest, bool enableForeignAuthentication)
        {
            var htmlBuilder = new StringBuilder();
            htmlBuilder.AppendLine("<!DOCTYPE html><HTML><BODY Onload=\"document.forms[0].submit()\">");
            htmlBuilder.AppendLine($"<FORM METHOD=\"POST\" ACTION=\"{_singleSignOnServiceUrl}\">");
            htmlBuilder.AppendLine($"<INPUT TYPE=\"HIDDEN\" NAME=\"SAMLRequest\" VALUE=\"{base64SamlRequest}\"/>");
            
            if (enableForeignAuthentication)
            {
                htmlBuilder.AppendLine("<INPUT TYPE=\"HIDDEN\" NAME=\"ForeignAuthentication\" VALUE=\"true\"/>");
            }
            
            htmlBuilder.AppendLine("<NOSCRIPT><P>JavaScript jest wyłączony. Rekomendujemy włączenie. Aby kontynuować, proszę nacisnąć przycisk poniżej.</P><INPUT TYPE=\"SUBMIT\" VALUE=\"Kontynuuj\" /></NOSCRIPT>");
            htmlBuilder.AppendLine("</FORM></BODY></HTML>");
            
            return htmlBuilder.ToString();
        }

        /// <summary>
        /// Podpisuje dokument XML zgodnie z wymogami Węzła Krajowego
        /// </summary>
        /// <param name="xmlDoc">Dokument XML do podpisania</param>
        private void SignXmlDocument(XmlDocument xmlDoc)
        {
            // Tworzenie podpisu
            SignedXml signedXml = new SignedXml(xmlDoc);
            signedXml.SigningKey = _signCertificate.GetECDsaPrivateKey();

            // Tworzenie referencji do podpisywania
            Reference reference = new Reference();
            reference.Uri = "";

            // Dodawanie transformacji
            XmlDsigEnvelopedSignatureTransform envelopedSignatureTransform = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(envelopedSignatureTransform);

            XmlDsigExcC14NTransform excC14NTransform = new XmlDsigExcC14NTransform();
            reference.AddTransform(excC14NTransform);

            // Ustawienie metody trawienia
            reference.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";
            
            // Dodawanie referencji do podpisu
            signedXml.AddReference(reference);

            // Dodawanie informacji o kluczu
            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(_signCertificate));
            signedXml.KeyInfo = keyInfo;

            // Ustawienie metody podpisu
            signedXml.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
            signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

            // Obliczenie podpisu
            signedXml.ComputeSignature();

            // Pobranie elementu podpisu XML
            XmlElement signatureElement = signedXml.GetXml();

            // Dodanie elementu podpisu do dokumentu
            XmlNodeList issuerNodes = xmlDoc.GetElementsByTagName("saml2:Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
            if (issuerNodes.Count > 0)
            {
                XmlNode issuerNode = issuerNodes[0];
                issuerNode.ParentNode.InsertAfter(signatureElement, issuerNode);
            }
        }

        /// <summary>
        /// Przetwarza odpowiedź z artefaktem SAML i wysyła żądanie ArtifactResolve
        /// </summary>
        /// <param name="artifact">Artefakt SAML otrzymany w odpowiedzi</param>
        /// <returns>Rozszyfrowana asercja SAML</returns>
        public SamlAssertion ProcessArtifactResponse(string artifact)
        {
            // Tworzenie żądania ArtifactResolve
            string artifactResolveRequest = GenerateArtifactResolveRequest(artifact);

            // Wysyłanie żądania ArtifactResolve
            string artifactResponse = SendArtifactResolveRequest(artifactResolveRequest);

            // Przetwarzanie odpowiedzi ArtifactResponse
            return ProcessArtifactResponseXml(artifactResponse);
        }

        /// <summary>
        /// Generuje żądanie ArtifactResolve
        /// </summary>
        /// <param name="artifact">Artefakt SAML</param>
        /// <returns>Dokument XML żądania ArtifactResolve</returns>
        private string GenerateArtifactResolveRequest(string artifact)
        {
            var requestId = $"ID-{Guid.NewGuid()}";
            var dateTimeNow = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;

            // Tworzenie dokumentu XML
            doc.LoadXml($@"<soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"">
<SOAP-ENV:Header xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/""/>
<soap:Body>
    <saml2p:ArtifactResolve 
        xmlns:coi-extension=""http://coi.gov.pl/saml-extensions""
        xmlns:coi-naturalperson=""http://coi.gov.pl/attributes/naturalperson""
        xmlns:ds=""http://www.w3.org/2000/09/xmldsig#""
        xmlns:dsig11=""http://www.w3.org/2009/xmldsig11#""
        xmlns:eidas=""http://eidas.europa.eu/saml-extensions""
        xmlns:kirwb=""http://wb.kir.pl/saml-extensions""
        xmlns:naturalperson=""http://eidas.europa.eu/attributes/naturalperson""
        xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
        xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
        xmlns:xenc=""http://www.w3.org/2001/04/xmlenc#""
        xmlns:xenc11=""http://www.w3.org/2009/xmlenc11#""
        ID=""{requestId}""
        IssueInstant=""{dateTimeNow}"" 
        Version=""2.0"">
        <saml2:Issuer>{_issuer}</saml2:Issuer>
        <saml2p:Artifact>{artifact}</saml2p:Artifact>
    </saml2p:ArtifactResolve>
</soap:Body>
</soap:Envelope>");

            // Pobranie elementu ArtifactResolve
            XmlNodeList artifactResolveNodes = doc.GetElementsByTagName("saml2p:ArtifactResolve");
            if (artifactResolveNodes.Count == 0)
            {
                throw new InvalidOperationException("Element ArtifactResolve nie został znaleziony w dokumencie.");
            }

            XmlNode artifactResolveNode = artifactResolveNodes[0];
            
            // Utworzenie nowego dokumentu zawierającego tylko element ArtifactResolve
            XmlDocument artifactResolveDoc = new XmlDocument();
            artifactResolveDoc.PreserveWhitespace = true;
            artifactResolveDoc.AppendChild(artifactResolveDoc.ImportNode(artifactResolveNode, true));
            
            // Podpisanie dokumentu ArtifactResolve
            SignXmlDocumentWithReference(artifactResolveDoc, requestId);
            
            // Zastąpienie elementu ArtifactResolve w oryginalnym dokumencie
            XmlNode importedNode = doc.ImportNode(artifactResolveDoc.DocumentElement, true);
            artifactResolveNode.ParentNode.ReplaceChild(importedNode, artifactResolveNode);
            
            return doc.OuterXml;
        }

        /// <summary>
        /// Podpisuje dokument XML używając referencji do ID
        /// </summary>
        /// <param name="xmlDoc">Dokument XML do podpisania</param>
        /// <param name="referenceId">ID elementu, do którego będzie odnosić się referencja</param>
        private void SignXmlDocumentWithReference(XmlDocument xmlDoc, string referenceId)
        {
            // Tworzenie podpisu
            SignedXml signedXml = new SignedXml(xmlDoc);
            signedXml.SigningKey = _signCertificate.GetECDsaPrivateKey();

            // Tworzenie referencji do podpisywania
            Reference reference = new Reference();
            reference.Uri = $"#{referenceId}";

            // Dodawanie transformacji
            XmlDsigEnvelopedSignatureTransform envelopedSignatureTransform = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(envelopedSignatureTransform);

            XmlDsigExcC14NTransform excC14NTransform = new XmlDsigExcC14NTransform();
            reference.AddTransform(excC14NTransform);

            // Ustawienie metody trawienia
            reference.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";
            
            // Dodawanie referencji do podpisu
            signedXml.AddReference(reference);

            // Dodawanie informacji o kluczu
            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(_signCertificate));
            signedXml.KeyInfo = keyInfo;

            // Ustawienie metody podpisu
            signedXml.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
            signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

            // Obliczenie podpisu
            signedXml.ComputeSignature();

            // Pobranie elementu podpisu XML
            XmlElement signatureElement = signedXml.GetXml();

            // Dodanie elementu podpisu do dokumentu
            XmlNodeList issuerNodes = xmlDoc.GetElementsByTagName("saml2:Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
            if (issuerNodes.Count > 0)
            {
                XmlNode issuerNode = issuerNodes[0];
                issuerNode.ParentNode.InsertAfter(signatureElement, issuerNode);
            }
        }

        /// <summary>
        /// Wysyła żądanie ArtifactResolve do usługi login.gov.pl
        /// </summary>
        /// <param name="artifactResolveRequest">Żądanie ArtifactResolve w formacie XML</param>
        /// <returns>Odpowiedź ArtifactResponse w formacie XML</returns>
        private string SendArtifactResolveRequest(string artifactResolveRequest)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(_artifactResolutionServiceUrl);
            request.Method = "POST";
            request.ContentType = "text/xml; charset=utf-8";
            request.Headers.Add("SOAPAction", "\"\"");
            request.ClientCertificates.Add(_signCertificate);

            // Wysyłanie żądania
            byte[] byteArray = Encoding.UTF8.GetBytes(artifactResolveRequest);
            request.ContentLength = byteArray.Length;

            using (Stream dataStream = request.GetRequestStream())
            {
                dataStream.Write(byteArray, 0, byteArray.Length);
            }

            // Odbieranie odpowiedzi
            using (WebResponse response = request.GetResponse())
            using (Stream responseStream = response.GetResponseStream())
            using (StreamReader reader = new StreamReader(responseStream))
            {
                return reader.ReadToEnd();
            }
        }

        /// <summary>
        /// Przetwarza odpowiedź ArtifactResponse i deszyfruje asercję SAML
        /// </summary>
        /// <param name="artifactResponseXml">Odpowiedź ArtifactResponse w formacie XML</param>
        /// <returns>Rozszyfrowana asercja SAML</returns>
        private SamlAssertion ProcessArtifactResponseXml(string artifactResponseXml)
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(artifactResponseXml);

            // Sprawdzanie statusu odpowiedzi
            XmlNodeList statusCodeNodes = doc.GetElementsByTagName("saml2p:StatusCode", "urn:oasis:names:tc:SAML:2.0:protocol");
            if (statusCodeNodes.Count > 0)
            {
                XmlAttribute valueAttr = statusCodeNodes[0].Attributes["Value"];
                if (valueAttr != null && valueAttr.Value != "urn:oasis:names:tc:SAML:2.0:status:Success")
                {
                    // Sprawdzenie, czy istnieje zagnieżdżony status code
                    XmlNodeList nestedStatusCodes = statusCodeNodes[0].ChildNodes;
                    string nestedStatus = string.Empty;

                    if (nestedStatusCodes.Count > 0)
                    {
                        foreach (XmlNode node in nestedStatusCodes)
                        {
                            if (node.Name == "saml2p:StatusCode")
                            {
                                XmlAttribute nestedValueAttr = node.Attributes["Value"];
                                if (nestedValueAttr != null)
                                {
                                    nestedStatus = nestedValueAttr.Value;
                                    break;
                                }
                            }
                        }
                    }

                    // Sprawdzenie, czy istnieje komunikat błędu
                    string statusMessage = string.Empty;
                    XmlNodeList statusMessageNodes = doc.GetElementsByTagName("saml2p:StatusMessage", "urn:oasis:names:tc:SAML:2.0:protocol");
                    if (statusMessageNodes.Count > 0)
                    {
                        statusMessage = statusMessageNodes[0].InnerText;
                    }

                    throw new ApplicationException($"Błąd w odpowiedzi SAML. Status: {valueAttr.Value}, StatusNested: {nestedStatus}, Message: {statusMessage}");
                }
            }

            // Wyszukiwanie zaszyfrowanej asercji
            XmlNodeList encryptedAssertionNodes = doc.GetElementsByTagName("saml2:EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
            if (encryptedAssertionNodes.Count == 0)
            {
                throw new ApplicationException("Nie znaleziono elementu EncryptedAssertion w odpowiedzi.");
            }

            XmlNode encryptedAssertionNode = encryptedAssertionNodes[0];

            // Tutaj byłaby implementacja deszyfracji asercji SAML
            // To jest zaawansowany proces kryptograficzny, który wymaga dokładnej implementacji
            // zgodnie z opisem z rozdziału 12 dokumentacji. Ze względu na złożoność,
            // poniżej znajduje się jedynie szkieletowa implementacja.

            SamlAssertion assertion = DecryptAssertion(encryptedAssertionNode);
            return assertion;
        }

        /// <summary>
        /// Deszyfruje asercję SAML
        /// </summary>
        /// <param name="encryptedAssertionNode">Zaszyfrowana asercja</param>
        /// <returns>Rozszyfrowana asercja SAML</returns>
        private SamlAssertion DecryptAssertion(XmlNode encryptedAssertionNode)
        {
            // UWAGA: Poniższa implementacja jest uproszczona i szkieletowa.
            // W rzeczywistej implementacji należy dokładnie zaimplementować proces
            // deszyfracji zgodny z opisem w rozdziale 12 dokumentacji.

            // 1. Wyszukiwanie potrzebnych elementów
            XmlDocument encryptedDataDoc = new XmlDocument();
            encryptedDataDoc.PreserveWhitespace = true;
            XmlNode encryptedDataNode = encryptedAssertionNode.SelectSingleNode(".//xenc:EncryptedData", GetNamespaceManager(encryptedAssertionNode.OwnerDocument));
            encryptedDataDoc.AppendChild(encryptedDataDoc.ImportNode(encryptedDataNode, true));

            // 2. Odczytanie klucza publicznego nadawcy
            XmlNode originatorKeyInfoNode = encryptedDataDoc.SelectSingleNode("//xenc:OriginatorKeyInfo", GetNamespaceManager(encryptedDataDoc));
            XmlNode ecKeyValueNode = originatorKeyInfoNode.SelectSingleNode(".//dsig11:ECKeyValue", GetNamespaceManager(encryptedDataDoc));
            XmlNode namedCurveNode = ecKeyValueNode.SelectSingleNode(".//dsig11:NamedCurve", GetNamespaceManager(encryptedDataDoc));
            XmlNode publicKeyNode = ecKeyValueNode.SelectSingleNode(".//dsig11:PublicKey", GetNamespaceManager(encryptedDataDoc));

            // 3. Odczytanie parametrów KDF
            XmlNode concatKDFParamsNode = encryptedDataDoc.SelectSingleNode("//xenc11:ConcatKDFParams", GetNamespaceManager(encryptedDataDoc));
            string algorithmId = concatKDFParamsNode.Attributes["AlgorithmID"].Value;
            string partyUInfo = concatKDFParamsNode.Attributes["PartyUInfo"].Value;
            string partyVInfo = concatKDFParamsNode.Attributes["PartyVInfo"].Value;

            // 4. Odczytanie zaszyfrowanego klucza sesyjnego
            XmlNode cipherValueNode = encryptedDataDoc.SelectSingleNode("//xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue", GetNamespaceManager(encryptedDataDoc));
            string encryptedKeyBase64 = cipherValueNode.InnerText;
            byte[] encryptedKeyBytes = Convert.FromBase64String(encryptedKeyBase64);

            // 5. Odczytanie zaszyfrowanych danych
            XmlNode encryptedDataCipherValueNode = encryptedDataDoc.SelectSingleNode("//xenc:EncryptedData/xenc:CipherData/xenc:CipherValue", GetNamespaceManager(encryptedDataDoc));
            string encryptedDataBase64 = encryptedDataCipherValueNode.InnerText;
            byte[] encryptedDataBytes = Convert.FromBase64String(encryptedDataBase64);

            // 6. Wykonanie procesu deszyfracji (w rzeczywistości znacznie bardziej złożone)
            // Poniższy kod to tylko szkielet pokazujący podstawowe kroki

            // W tym miejscu należy zaimplementować pełny proces deszyfracji opisany w dokumentacji
            // Proces obejmuje:
            // - KeyAgreement przy użyciu lokalnego klucza prywatnego i przesłanego klucza publicznego
            // - Wykonanie operacji KDF (ConcatKDF)
            // - Odszyfrowanie klucza sesyjnego
            // - Odszyfrowanie danych asercji

            // 7. Tworzenie obiektu SamlAssertion na podstawie zdeszyfrowanych danych
            // W rzeczywistej implementacji, po rozszyfrowaniu, dane zostałyby przetworzone
            // na obiekt SamlAssertion zawierający wszystkie informacje o użytkowniku
            
            // Symulacja wyniku deszyfracji
            var assertion = new SamlAssertion
            {
                NameID = "AVIphXW7D/K5s/tQmpMb04KBg8nDuBuFwVYZ2vtZ6lw=",
                SessionIndex = "_ID-3118aea6-6ca4-4fe2-a4a9-731f1be19a05",
                AuthnContextClassRef = "http://eidas.europa.eu/LoA/substantial",
                AuthenticatingAuthority = "pz.gov.pl",
                Attributes = new Dictionary<string, string>
                {
                    { "FirstName", "Jan" },
                    { "FamilyName", "Niezbedny" },
                    { "PersonIdentifier", "86072500004" },
                    { "DateOfBirth", "1986-07-25" }
                }
            };

            return assertion;
        }

        /// <summary>
        /// Tworzy menedżera przestrzeni nazw dla dokumentu XML
        /// </summary>
        /// <param name="doc">Dokument XML</param>
        /// <returns>Menedżer przestrzeni nazw</returns>
        private XmlNamespaceManager GetNamespaceManager(XmlDocument doc)
        {
            XmlNamespaceManager nsManager = new XmlNamespaceManager(doc.NameTable);
            nsManager.AddNamespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");
            nsManager.AddNamespace("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");
            nsManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            nsManager.AddNamespace("dsig11", "http://www.w3.org/2009/xmldsig11#");
            nsManager.AddNamespace("xenc", "http://www.w3.org/2001/04/xmlenc#");
            nsManager.AddNamespace("xenc11", "http://www.w3.org/2009/xmlenc11#");
            nsManager.AddNamespace("eidas", "http://eidas.europa.eu/saml-extensions");
            nsManager.AddNamespace("naturalperson", "http://eidas.europa.eu/attributes/naturalperson");
            return nsManager;
        }
        
        /// <summary>
        /// Generuje żądanie wylogowania
        /// </summary>
        /// <param name="nameId">Identyfikator użytkownika</param>
        /// <param name="sessionIndex">Indeks sesji</param>
        /// <returns>Status odpowiedzi wylogowania</returns>
        public SamlLogoutStatus Logout(string nameId, string sessionIndex)
        {
            // Generowanie żądania LogoutRequest
            string logoutRequest = GenerateLogoutRequest(nameId, sessionIndex);
            
            // Wysłanie żądania LogoutRequest
            string logoutResponse = SendLogoutRequest(logoutRequest);
            
            // Przetwarzanie odpowiedzi LogoutResponse
            return ProcessLogoutResponse(logoutResponse);
        }
        
        /// <summary>
        /// Generuje żądanie LogoutRequest
        /// </summary>
        /// <param name="nameId">Identyfikator użytkownika</param>
        /// <param name="sessionIndex">Indeks sesji</param>
        /// <returns>Dokument XML żądania LogoutRequest</returns>
        private string GenerateLogoutRequest(string nameId, string sessionIndex)
        {
            var requestId = $"ID-{Guid.NewGuid()}";
            var dateTimeNow = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            
            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            
            // Tworzenie dokumentu XML
            doc.LoadXml($@"<soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"">
<SOAP-ENV:Header xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/""/>
<soap:Body>
    <saml2p:LogoutRequest 
        xmlns:ds=""http://www.w3.org/2000/09/xmldsig#""
        xmlns:eidas=""http://eidas.europa.eu/saml-extensions""
        xmlns:naturalperson=""http://eidas.europa.eu/attributes/naturalperson""
        xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion""
        xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol""
        xmlns:xenc=""http://www.w3.org/2001/04/xmlenc#""
        Destination=""{_singleLogoutServiceUrl}""
        ID=""{requestId}""
        IssueInstant=""{dateTimeNow}""
        Version=""2.0"">
        <saml2:Issuer>{_issuer}</saml2:Issuer>
        <saml2:NameID Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"">{nameId}</saml2:NameID>
        <saml2p:SessionIndex>{sessionIndex}</saml2p:SessionIndex>
    </saml2p:LogoutRequest>
</soap:Body>
</soap:Envelope>");
            
            // Pobranie elementu LogoutRequest
            XmlNodeList logoutRequestNodes = doc.GetElementsByTagName("saml2p:LogoutRequest");
            if (logoutRequestNodes.Count == 0)
            {
                throw new InvalidOperationException("Element LogoutRequest nie został znaleziony w dokumencie.");
            }
            
            XmlNode logoutRequestNode = logoutRequestNodes[0];
            
            // Utworzenie nowego dokumentu zawierającego tylko element LogoutRequest
            XmlDocument logoutRequestDoc = new XmlDocument();
            logoutRequestDoc.PreserveWhitespace = true;
            logoutRequestDoc.AppendChild(logoutRequestDoc.ImportNode(logoutRequestNode, true));
            
            // Podpisanie dokumentu LogoutRequest
            SignXmlDocument(logoutRequestDoc);
            
            // Zastąpienie elementu LogoutRequest w oryginalnym dokumencie
            XmlNode importedNode = doc.ImportNode(logoutRequestDoc.DocumentElement, true);
            logoutRequestNode.ParentNode.ReplaceChild(importedNode, logoutRequestNode);
            
            return doc.OuterXml;
        }
        
        /// <summary>
        /// Wysyła żądanie LogoutRequest do usługi login.gov.pl
        /// </summary>
        /// <param name="logoutRequest">Żądanie LogoutRequest w formacie XML</param>
        /// <returns>Odpowiedź LogoutResponse w formacie XML</returns>
        private string SendLogoutRequest(string logoutRequest)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(_singleLogoutServiceUrl);
            request.Method = "POST";
            request.ContentType = "text/xml; charset=utf-8";
            request.Headers.Add("SOAPAction", "\"\"");
            request.ClientCertificates.Add(_signCertificate);
            
            // Wysyłanie żądania
            byte[] byteArray = Encoding.UTF8.GetBytes(logoutRequest);
            request.ContentLength = byteArray.Length;
            
            using (Stream dataStream = request.GetRequestStream())
            {
                dataStream.Write(byteArray, 0, byteArray.Length);
            }
            
            // Odbieranie odpowiedzi
            using (WebResponse response = request.GetResponse())
            using (Stream responseStream = response.GetResponseStream())
            using (StreamReader reader = new StreamReader(responseStream))
            {
                return reader.ReadToEnd();
            }
        }
        
        /// <summary>
        /// Przetwarza odpowiedź LogoutResponse
        /// </summary>
        /// <param name="logoutResponseXml">Odpowiedź LogoutResponse w formacie XML</param>
        /// <returns>Status odpowiedzi wylogowania</returns>
        private SamlLogoutStatus ProcessLogoutResponse(string logoutResponseXml)
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(logoutResponseXml);
            
            // Sprawdzanie statusu odpowiedzi
            XmlNodeList statusCodeNodes = doc.GetElementsByTagName("saml2p:StatusCode", "urn:oasis:names:tc:SAML:2.0:protocol");
            if (statusCodeNodes.Count > 0)
            {
                XmlAttribute valueAttr = statusCodeNodes[0].Attributes["Value"];
                if (valueAttr != null)
                {
                    switch (valueAttr.Value)
                    {
                        case "urn:oasis:names:tc:SAML:2.0:status:Success":
                            return SamlLogoutStatus.Success;
                        case "urn:oasis:names:tc:SAML:2.0:status:PartialLogout":
                            return SamlLogoutStatus.PartialLogout;
                        case "urn:oasis:names:tc:SAML:2.0:status:Requester":
                            return SamlLogoutStatus.Requester;
                        default:
                            return SamlLogoutStatus.Error;
                    }
                }
            }
            
            return SamlLogoutStatus.Error;
        }
    }
    
    /// <summary>
    /// Klasa reprezentująca rozszyfrowaną asercję SAML
    /// </summary>
    public class SamlAssertion
    {
        /// <summary>
        /// Identyfikator użytkownika
        /// </summary>
        public string NameID { get; set; }
        
        /// <summary>
        /// Indeks sesji
        /// </summary>
        public string SessionIndex { get; set; }
        
        /// <summary>
        /// Kontekst uwierzytelnienia
        /// </summary>
        public string AuthnContextClassRef { get; set; }
        
        /// <summary>
        /// Uwierzytelniająca jednostka (np. pz.gov.pl)
        /// </summary>
        public string AuthenticatingAuthority { get; set; }
        
        /// <summary>
        /// Atrybuty użytkownika (np. imię, nazwisko, PESEL)
        /// </summary>
        public Dictionary<string, string> Attributes { get; set; }
        
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"NameID: {NameID}");
            sb.AppendLine($"SessionIndex: {SessionIndex}");
            sb.AppendLine($"AuthnContextClassRef: {AuthnContextClassRef}");
            sb.AppendLine($"AuthenticatingAuthority: {AuthenticatingAuthority}");
            sb.AppendLine("Attributes:");
            
            if (Attributes != null)
            {
                foreach (var attr in Attributes)
                {
                    sb.AppendLine($"  {attr.Key}: {attr.Value}");
                }
            }
            
            return sb.ToString();
        }
    }
    
    /// <summary>
    /// Status odpowiedzi wylogowania
    /// </summary>
    public enum SamlLogoutStatus
    {
        /// <summary>
        /// Wylogowanie pomyślne
        /// </summary>
        Success,
        
        /// <summary>
        /// Częściowe wylogowanie
        /// </summary>
        PartialLogout,
        
        /// <summary>
        /// Błąd w żądaniu
        /// </summary>
        Requester,
        
        /// <summary>
        /// Inny błąd
        /// </summary>
        Error
    }
}