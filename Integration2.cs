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
            try
            {
                // 1. Wyszukiwanie potrzebnych elementów
                XmlDocument encryptedDataDoc = new XmlDocument();
                encryptedDataDoc.PreserveWhitespace = true;
                XmlNode encryptedDataNode = encryptedAssertionNode.SelectSingleNode(".//xenc:EncryptedData", GetNamespaceManager(encryptedAssertionNode.OwnerDocument));
                if (encryptedDataNode == null)
                {
                    throw new ApplicationException("Nie znaleziono elementu EncryptedData w zaszyfrowanej asercji.");
                }
                encryptedDataDoc.AppendChild(encryptedDataDoc.ImportNode(encryptedDataNode, true));

                // 2. Odczytanie klucza publicznego nadawcy (efemerycznego)
                XmlNamespaceManager nsManager = GetNamespaceManager(encryptedDataDoc);
                
                XmlNode keyInfoNode = encryptedDataDoc.SelectSingleNode("//xenc:EncryptedData/ds:KeyInfo", nsManager);
                if (keyInfoNode == null)
                {
                    throw new ApplicationException("Nie znaleziono elementu KeyInfo w zaszyfrowanej asercji.");
                }
                
                XmlNode encryptedKeyNode = keyInfoNode.SelectSingleNode(".//xenc:EncryptedKey", nsManager);
                if (encryptedKeyNode == null)
                {
                    throw new ApplicationException("Nie znaleziono elementu EncryptedKey w zaszyfrowanej asercji.");
                }
                
                XmlNode agreementMethodNode = encryptedKeyNode.SelectSingleNode(".//xenc:AgreementMethod", nsManager);
                if (agreementMethodNode == null)
                {
                    throw new ApplicationException("Nie znaleziono elementu AgreementMethod w zaszyfrowanej asercji.");
                }
                
                XmlNode originatorKeyInfoNode = agreementMethodNode.SelectSingleNode(".//xenc:OriginatorKeyInfo", nsManager);
                if (originatorKeyInfoNode == null)
                {
                    throw new ApplicationException("Nie znaleziono elementu OriginatorKeyInfo w zaszyfrowanej asercji.");
                }
                
                XmlNode keyValueNode = originatorKeyInfoNode.SelectSingleNode(".//ds:KeyValue", nsManager);
                if (keyValueNode == null)
                {
                    throw new ApplicationException("Nie znaleziono elementu KeyValue w zaszyfrowanej asercji.");
                }
                
                XmlNode ecKeyValueNode = keyValueNode.SelectSingleNode(".//dsig11:ECKeyValue", nsManager);
                if (ecKeyValueNode == null)
                {
                    throw new ApplicationException("Nie znaleziono elementu ECKeyValue w zaszyfrowanej asercji.");
                }
                
                XmlNode namedCurveNode = ecKeyValueNode.SelectSingleNode(".//dsig11:NamedCurve", nsManager);
                if (namedCurveNode == null)
                {
                    throw new ApplicationException("Nie znaleziono elementu NamedCurve w zaszyfrowanej asercji.");
                }
                
                XmlNode publicKeyNode = ecKeyValueNode.SelectSingleNode(".//dsig11:PublicKey", nsManager);
                if (publicKeyNode == null)
                {
                    throw new ApplicationException("Nie znaleziono elementu PublicKey w zaszyfrowanej asercji.");
                }
                
                // Odczytanie parametrów krzywej eliptycznej
                string namedCurveUri = namedCurveNode.Attributes["URI"]?.Value;
                if (string.IsNullOrEmpty(namedCurveUri))
                {
                    throw new ApplicationException("Nie znaleziono atrybutu URI w elemencie NamedCurve.");
                }
                
                // Sprawdzamy, czy jest to krzywa NIST P-256 (secp256r1)
                bool isNistP256 = namedCurveUri == "urn:oid:1.2.840.10045.3.1.7";
                if (!isNistP256)
                {
                    throw new ApplicationException($"Nieobsługiwana krzywa eliptyczna: {namedCurveUri}. Oczekiwano krzywej NIST P-256.");
                }
                
                // Odczytanie klucza publicznego nadawcy z formatu base64
                byte[] publicKeyBytes = Convert.FromBase64String(publicKeyNode.InnerText);
                
                // 3. Odczytanie parametrów KDF (Key Derivation Function)
                XmlNode keyDerivationMethodNode = agreementMethodNode.SelectSingleNode(".//xenc11:KeyDerivationMethod", nsManager);
                if (keyDerivationMethodNode == null)
                {
                    throw new ApplicationException("Nie znaleziono elementu KeyDerivationMethod w zaszyfrowanej asercji.");
                }
                
                string kdfAlgorithm = keyDerivationMethodNode.Attributes["Algorithm"]?.Value;
                if (string.IsNullOrEmpty(kdfAlgorithm) || kdfAlgorithm != "http://www.w3.org/2009/xmlenc11#ConcatKDF")
                {
                    throw new ApplicationException($"Nieobsługiwany algorytm KDF: {kdfAlgorithm}. Oczekiwano ConcatKDF.");
                }
                
                XmlNode concatKDFParamsNode = keyDerivationMethodNode.SelectSingleNode(".//xenc11:ConcatKDFParams", nsManager);
                if (concatKDFParamsNode == null)
                {
                    throw new ApplicationException("Nie znaleziono elementu ConcatKDFParams w zaszyfrowanej asercji.");
                }
                
                string algorithmId = concatKDFParamsNode.Attributes["AlgorithmID"]?.Value;
                string partyUInfo = concatKDFParamsNode.Attributes["PartyUInfo"]?.Value;
                string partyVInfo = concatKDFParamsNode.Attributes["PartyVInfo"]?.Value;
                
                if (string.IsNullOrEmpty(algorithmId) || string.IsNullOrEmpty(partyUInfo) || string.IsNullOrEmpty(partyVInfo))
                {
                    throw new ApplicationException("Brak wymaganych parametrów ConcatKDF.");
                }
                
                // 4. Odczytanie zaszyfrowanego klucza sesyjnego
                XmlNode cipherValueNode = encryptedKeyNode.SelectSingleNode(".//xenc:CipherData/xenc:CipherValue", nsManager);
                if (cipherValueNode == null)
                {
                    throw new ApplicationException("Nie znaleziono elementu CipherValue dla EncryptedKey.");
                }
                
                string encryptedKeyBase64 = cipherValueNode.InnerText;
                byte[] encryptedKeyBytes = Convert.FromBase64String(encryptedKeyBase64);
                
                // 5. Odczytanie zaszyfrowanych danych
                XmlNode encryptedDataCipherValueNode = encryptedDataDoc.SelectSingleNode("//xenc:EncryptedData/xenc:CipherData/xenc:CipherValue", nsManager);
                if (encryptedDataCipherValueNode == null)
                {
                    throw new ApplicationException("Nie znaleziono elementu CipherValue dla EncryptedData.");
                }
                
                string encryptedDataBase64 = encryptedDataCipherValueNode.InnerText;
                byte[] encryptedDataBytes = Convert.FromBase64String(encryptedDataBase64);
                
                // 6. Wykonanie procesu deszyfracji
                
                // 6.1. Utworzenie punktu klucza publicznego na krzywej eliptycznej
                ECDsaCng privateKeyECDsa = _encryptionCertificate.GetECDsaPrivateKey() as ECDsaCng;
                if (privateKeyECDsa == null)
                {
                    throw new ApplicationException("Nie można uzyskać klucza prywatnego ECDsa.");
                }
                
                // Uzyskanie informacji o kluczu prywatnym
                CngKey privateKey = privateKeyECDsa.Key;
                
                // Utworzenie punktu klucza publicznego nadawcy z przesłanych danych
                // Odczytanie współrzędnych x,y z publicKeyBytes i utworzenie punktu ECPoint
                // Format klucza publicznego to X9.62 uncompressed point (0x04 || x || y)
                if (publicKeyBytes.Length != 65 || publicKeyBytes[0] != 0x04)
                {
                    throw new ApplicationException("Nieprawidłowy format klucza publicznego. Oczekiwano formatu X9.62 uncompressed.");
                }
                
                byte[] xCoord = new byte[32]; // 256 bits = 32 bytes
                byte[] yCoord = new byte[32]; // 256 bits = 32 bytes
                
                // Kopiowanie współrzędnych x i y
                Buffer.BlockCopy(publicKeyBytes, 1, xCoord, 0, 32); // x starts after the first byte (0x04)
                Buffer.BlockCopy(publicKeyBytes, 33, yCoord, 0, 32); // y starts after x

                // 6.2. Wykonanie operacji KeyAgreement (ECDH)
                // W .NET Core można użyć klasy ECDiffieHellman do wykonania operacji ECDH-ES
                // W starszych wersjach .NET, trzeba użyć niskopoziomowych mechanizmów CNG
                byte[] secretZ;
                using (ECDiffieHellmanCng ecdh = new ECDiffieHellmanCng(privateKey))
                {
                    // Utworzenie klucza publicznego nadawcy jako ECDiffieHellmanPublicKey
                    ECParameters parameters = new ECParameters
                    {
                        Curve = ECCurve.NamedCurves.nistP256, // NIST P-256 curve
                        Q = new ECPoint
                        {
                            X = xCoord,
                            Y = yCoord
                        }
                    };
                    
                    using (ECDiffieHellman publicEcdh = ECDiffieHellman.Create(parameters))
                    {
                        // Uzyskanie publicznego klucza w formacie ECDiffieHellmanPublicKey
                        ECDiffieHellmanPublicKey publicKey = publicEcdh.PublicKey;
                        
                        // Wykonanie operacji KeyAgreement
                        secretZ = ecdh.DeriveKeyMaterial(publicKey);
                    }
                }
                
                // 6.3. Wykonanie operacji KDF (ConcatKDF)
                // Zgodnie z dokumentacją, algorytmId, partyUInfo i partyVInfo są w formacie binaryHex
                // i zawierają prefiks długości (DataLen || Data)
                byte[] algorithmIdBytes = HexStringToBytes(algorithmId);
                byte[] partyUInfoBytes = HexStringToBytes(partyUInfo);
                byte[] partyVInfoBytes = HexStringToBytes(partyVInfo);
                
                // Składamy dane wejściowe dla KDF
                byte[] kdfInput = ConcatenateDeriveKey(secretZ, algorithmIdBytes, partyUInfoBytes, partyVInfoBytes);
                
                // Wykonanie operacji KDF (ConcatKDF z SHA-256)
                byte[] derivedKey = PerformConcatKDF(kdfInput, 32); // 32 bytes = 256 bits for AES-256
                
                // 6.4. Odszyfrowanie klucza sesyjnego
                // Klucz AES-256 do rozwinięcia klucza
                using (Aes aes = Aes.Create())
                {
                    aes.Key = derivedKey;
                    aes.Mode = CipherMode.ECB; // AES-KW używa ECB mode
                    aes.Padding = PaddingMode.None;
                    
                    // AES Key Unwrap (AES-KW)
                    byte[] unwrappedKey = AesKeyUnwrap(aes, encryptedKeyBytes);
                    
                    // 6.5. Odszyfrowanie danych asercji
                    // Odczytanie IV (pierwszy 16 bajtów zaszyfrowanych danych)
                    byte[] iv = new byte[12]; // GCM uses 12-byte IV (96 bits)
                    Buffer.BlockCopy(encryptedDataBytes, 0, iv, 0, 12);
                    
                    // Rzeczywiste zaszyfrowane dane (bez IV)
                    byte[] actualEncryptedData = new byte[encryptedDataBytes.Length - 12];
                    Buffer.BlockCopy(encryptedDataBytes, 12, actualEncryptedData, 0, actualEncryptedData.Length);
                    
                    // Deszyfracja danych używając AES-GCM
                    byte[] decryptedData = AesGcmDecrypt(unwrappedKey, iv, actualEncryptedData);
                    
                    // Konwersja odszyfrowanych danych na XML
                    string decryptedXml = Encoding.UTF8.GetString(decryptedData);
                    
                    // Parsowanie odszyfrowanej asercji XML
                    return ParseAssertionXml(decryptedXml);
                }
            }
            catch (Exception ex)
            {
                // W przypadku błędu deszyfracji, zapisz szczegóły w logach
                Console.WriteLine($"Błąd deszyfracji asercji: {ex.Message}");
                Console.WriteLine($"StackTrace: {ex.StackTrace}");
                
                throw new ApplicationException($"Nie udało się odszyfrować asercji: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Wykonuje operację AES Key Unwrap (AES-KW) do rozwinięcia klucza
        /// </summary>
        /// <param name="aes">Instancja AES z ustawionym kluczem</param>
        /// <param name="wrappedKey">Zawinięty klucz</param>
        /// <returns>Rozwinięty klucz</returns>
        private byte[] AesKeyUnwrap(Aes aes, byte[] wrappedKey)
        {
            // Implementacja algorytmu AES Key Unwrap zgodnie z RFC 3394
            // W .NET brak wbudowanej implementacji AES-KW, więc trzeba zaimplementować algorytm
            
            if (wrappedKey.Length % 8 != 0 || wrappedKey.Length < 16)
            {
                throw new ArgumentException("Nieprawidłowa długość zawijającego klucza.");
            }
            
            int n = wrappedKey.Length / 8 - 1;
            byte[] a = new byte[8];
            byte[] r = new byte[wrappedKey.Length - 8];
            
            // Inicjalizacja
            Buffer.BlockCopy(wrappedKey, 0, a, 0, 8);
            Buffer.BlockCopy(wrappedKey, 8, r, 0, wrappedKey.Length - 8);
            
            byte[][] r2d = new byte[n][];
            for (int i = 0; i < n; i++)
            {
                r2d[i] = new byte[8];
                Buffer.BlockCopy(r, i * 8, r2d[i], 0, 8);
            }
            
            // Stała używana w procesie rozwijania klucza
            byte[] iv = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
            
            // Główna pętla rozwijania klucza
            for (int j = 5; j >= 0; j--)
            {
                for (int i = n; i >= 1; i--)
                {
                    byte[] buffer = new byte[16];
                    
                    // A ^ t gdzie t = n*j+i
                    for (int k = 0; k < 8; k++)
                    {
                        a[k] ^= (byte)((n * j + i) >> ((7 - k) * 8) & 0xFF);
                    }
                    
                    // Przygotowanie bloku do deszyfracji
                    Buffer.BlockCopy(a, 0, buffer, 0, 8);
                    Buffer.BlockCopy(r2d[i - 1], 0, buffer, 8, 8);
                    
                    // Deszyfracja
                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    {
                        byte[] decrypted = decryptor.TransformFinalBlock(buffer, 0, 16);
                        
                        // Aktualizacja A i R[i]
                        Buffer.BlockCopy(decrypted, 0, a, 0, 8);
                        Buffer.BlockCopy(decrypted, 8, r2d[i - 1], 0, 8);
                    }
                }
            }
            
            // Weryfikacja poprawności rozwijania klucza
            if (!a.SequenceEqual(iv))
            {
                throw new CryptographicException("Błąd rozwijania klucza: nieprawidłowa stała integralności.");
            }
            
            // Łączenie wyników
            byte[] result = new byte[n * 8];
            for (int i = 0; i < n; i++)
            {
                Buffer.BlockCopy(r2d[i], 0, result, i * 8, 8);
            }
            
            return result;
        }
        
        /// <summary>
        /// Wykonuje operację AES-GCM deszyfracji
        /// </summary>
        /// <param name="key">Klucz AES</param>
        /// <param name="iv">Wektor inicjalizacyjny</param>
        /// <param name="encryptedData">Zaszyfrowane dane</param>
        /// <returns>Odszyfrowane dane</returns>
        private byte[] AesGcmDecrypt(byte[] key, byte[] iv, byte[] encryptedData)
        {
            // W .NET Framework nie ma wbudowanej implementacji AES-GCM
            // W .NET Core 3.0+ można użyć AesGcm
            // Poniżej przykład dla .NET Core 3.0+
            
#if NETCOREAPP3_0_OR_GREATER
            // Tag uwierzytelniający jest ostatnie 16 bajtów
            int ciphertextLength = encryptedData.Length - 16;
            byte[] ciphertext = new byte[ciphertextLength];
            byte[] tag = new byte[16];
            
            Buffer.BlockCopy(encryptedData, 0, ciphertext, 0, ciphertextLength);
            Buffer.BlockCopy(encryptedData, ciphertextLength, tag, 0, 16);
            
            byte[] plaintext = new byte[ciphertextLength];
            
            using (var aesGcm = new AesGcm(key))
            {
                aesGcm.Decrypt(iv, ciphertext, tag, plaintext);
            }
            
            return plaintext;
#else
            // W starszych wersjach .NET można użyć biblioteki BouncyCastle
            // lub innej biblioteki kryptograficznej obsługującej AES-GCM
            
            // Przykład z użyciem BouncyCastle:
            // Aby użyć BouncyCastle, należy dodać referencję do biblioteki:
            // PM> Install-Package BouncyCastle
            /*
            var cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
            var parameters = new AeadParameters(new KeyParameter(key), 128, iv);
            
            cipher.Init(false, parameters);
            
            byte[] plaintext = new byte[cipher.GetOutputSize(encryptedData.Length)];
            int len = cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, plaintext, 0);
            len += cipher.DoFinal(plaintext, len);
            
            // Jeśli len jest mniejszy niż plaintext.Length, trzeba skopiować tylko len bajtów
            if (len < plaintext.Length)
            {
                byte[] result = new byte[len];
                Buffer.BlockCopy(plaintext, 0, result, 0, len);
                return result;
            }
            
            return plaintext;
            */
            
            // Dla uproszczenia, w tym przykładzie zwracamy puste dane
            // W rzeczywistej implementacji należy użyć odpowiedniej biblioteki
            throw new NotImplementedException("Deszyfracja AES-GCM wymaga .NET Core 3.0+ lub biblioteki BouncyCastle.");
#endif
        }
        
        /// <summary>
        /// Wykonuje operację ConcatKDF zgodnie ze specyfikacją
        /// </summary>
        /// <param name="kdfInput">Dane wejściowe dla KDF</param>
        /// <param name="keyLength">Długość wynikowego klucza w bajtach</param>
        /// <returns>Wyprowadzony klucz</returns>
        private byte[] PerformConcatKDF(byte[] kdfInput, int keyLength)
        {
            // Implementacja algorytmu ConcatKDF zgodnie z NIST SP 800-56A
            
            using (SHA256 sha256 = SHA256.Create())
            {
                // Dla klucza 256-bitowego (32 bajty) wystarczy jedna iteracja
                byte[] counterBytes = { 0, 0, 0, 1 }; // Counter = 1 (big-endian)
                
                // Konkatenacja: Counter || Z || OtherInfo
                byte[] dataToHash = new byte[4 + kdfInput.Length];
                Buffer.BlockCopy(counterBytes, 0, dataToHash, 0, 4);
                Buffer.BlockCopy(kdfInput, 0, dataToHash, 4, kdfInput.Length);
                
                // Obliczenie skrótu
                byte[] derivedKey = sha256.ComputeHash(dataToHash);
                
                // Jeśli potrzebujemy więcej niż 32 bajty, trzeba wykonać więcej iteracji
                if (keyLength <= 32)
                {
                    // Jeśli potrzebujemy mniej niż 32 bajty, obcinamy wynik
                    if (keyLength < 32)
                    {
                        byte[] result = new byte[keyLength];
                        Buffer.BlockCopy(derivedKey, 0, result, 0, keyLength);
                        return result;
                    }
                    
                    return derivedKey;
                }
                else
                {
                    // Implementacja dla kluczy dłuższych niż 32 bajty
                    // W przypadku AES-256, nie będziemy potrzebować tej części
                    throw new ArgumentException("Nie obsługiwana długość klucza powyżej 32 bajtów.");
                }
            }
        }
        
        /// <summary>
        /// Konkatenuje dane dla operacji KDF
        /// </summary>
        /// <param name="secretZ">Sekret Z uzyskany z KeyAgreement</param>
        /// <param name="algorithmId">Identyfikator algorytmu</param>
        /// <param name="partyUInfo">Informacje o nadawcy</param>
        /// <param name="partyVInfo">Informacje o odbiorcy</param>
        /// <returns>Skonkatenowane dane</returns>
        private byte[] ConcatenateDeriveKey(byte[] secretZ, byte[] algorithmId, byte[] partyUInfo, byte[] partyVInfo)
        {
            // Zgodnie z dokumentacją, dane wejściowe dla KDF to Z || OtherInfo
            // gdzie OtherInfo to algorithmId || partyUInfo || partyVInfo
            
            int totalLength = secretZ.Length + algorithmId.Length + partyUInfo.Length + partyVInfo.Length;
            byte[] result = new byte[totalLength];
            
            int offset = 0;
            Buffer.BlockCopy(secretZ, 0, result, offset, secretZ.Length);
            offset += secretZ.Length;
            
            Buffer.BlockCopy(algorithmId, 0, result, offset, algorithmId.Length);
            offset += algorithmId.Length;
            
            Buffer.BlockCopy(partyUInfo, 0, result, offset, partyUInfo.Length);
            offset += partyUInfo.Length;
            
            Buffer.BlockCopy(partyVInfo, 0, result, offset, partyVInfo.Length);
            
            

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