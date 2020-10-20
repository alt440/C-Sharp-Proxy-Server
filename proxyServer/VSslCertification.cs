using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Net.Sockets;
using System.Net;
using System.Windows.Forms;
using Microsoft.Win32.SafeHandles;
using System.IO;
using System.Security.Cryptography;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
using System.Security.Authentication;
using System.Text.RegularExpressions;
using appCom;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Pkcs;
using System.Net.Http;

namespace proxyServer
{
    public class VSslCertification : IService, ISettings, IHelp, IDisposable
    {
        //IDisposable Implementation

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                _helpFile = null;
                _pRestore = null;
                logger = null;
                if (SslProt != null) Array.Clear(SslProt, 0, SslProt.Length);
                SslProt = null;
                self = null;
                console = null;
            }

            disposed = true;
        }

        //IHelp implementation

        private string _helpFile = "";

        public string HelpFile
        {
            get { return _helpFile; }
            set
            {
                if (File.Exists(value)) _helpFile = value;
            }
        }

        //ISettings implementation

        public void LoadSettings(KeyValuePair<string, string> kvp)
        {
            string key = kvp.Key.ToLower();
            string value = kvp.Value.ToLower();
            if (key == "state") Started = (value == "true") ? true : false;
            if (key == "use_ca") UseCASign = (value == "true") ? true : false;
            if (key == "protocols") SetProtocols(StringToProtocols(value));
            if (key == "state_autogen") AutoGenerate = (value == "true") ? true : false;
        }

        public void WriteSettings(System.Xml.XmlWriter xml)
        {
            xml.WriteStartElement("settings_start");
            xml.WriteElementString("state", (Started) ? "true" : "false");
            xml.WriteElementString("use_ca", (UseCASign) ? "true" : "false");
            if (SslProt.Length > 0) xml.WriteElementString("protocols", ProtocolToString());
            xml.WriteElementString("state_autogen", (AutoGenerate) ? "true" : "false");
            xml.WriteEndElement();
        }

        //IService Implementation

        private bool _started = false;
        private bool _selfInteractive = false;
        private string _pRestore = "";

        public bool Started
        {
            get { return _started; }
            set { _started = value; }
        }

        public bool SelfInteractive
        {
            get { return _selfInteractive; }
            set { _selfInteractive = value; }
        }

        public string PRestore
        {
            get { return _pRestore; }
            set { _pRestore = value; }
        }

        public void WarningMessage()
        {
            logger.Log("SSL Certification is not started!", VLogger.LogLevel.warning);
        }


        //Main SSL Cert class

        private VLogger logger;
        private SslProtObj[] SslProt;
        private static VSslCertification self;
        public bool AutoGenerate = true;
        public bool UseCASign = false;
        private VConsole console;

        //https://github.com/rlipscombe/bouncy-castle-csharp
        //Blog Site: http://blog.differentpla.net/blog/2013/03/24/bouncy-castle-being-a-certificate-authority
        public class CertificateGenerator
        {
            public static X509Certificate2 LoadCertificate(string issuerFileName, string password)
            {
                // We need to pass 'Exportable', otherwise we can't get the private key.
                var issuerCertificate = new X509Certificate2(issuerFileName, password, X509KeyStorageFlags.Exportable);
                return issuerCertificate;
            }

            public static X509Certificate2 IssueCertificate(string subjectName, X509Certificate2 issuerCertificate, string[] subjectAlternativeNames, KeyPurposeID[] usages)
            {
                // It's self-signed, so these are the same.
                var issuerName = issuerCertificate.Subject;

                var random = GetSecureRandom();
                var subjectKeyPair = GenerateKeyPair(random, 2048);

                var issuerKeyPair = DotNetUtilities.GetKeyPair(issuerCertificate.PrivateKey);

                var serialNumber = GenerateSerialNumber(random);
                var issuerSerialNumber = new BigInteger(issuerCertificate.GetSerialNumber());

                const bool isCertificateAuthority = false;
                var certificate = GenerateCertificate(random, subjectName, subjectKeyPair, serialNumber,
                                                      subjectAlternativeNames, issuerName, issuerKeyPair,
                                                      issuerSerialNumber, isCertificateAuthority,
                                                      usages);
                return ConvertCertificate(certificate, subjectKeyPair, random);
            }

            public static X509Certificate2 CreateCertificateAuthorityCertificate(string subjectName, string[] subjectAlternativeNames, KeyPurposeID[] usages)
            {
                // It's self-signed, so these are the same.
                var issuerName = subjectName;

                var random = GetSecureRandom();
                var subjectKeyPair = GenerateKeyPair(random, 2048);

                // It's self-signed, so these are the same.
                var issuerKeyPair = subjectKeyPair;

                var serialNumber = GenerateSerialNumber(random);
                var issuerSerialNumber = serialNumber; // Self-signed, so it's the same serial number.

                const bool isCertificateAuthority = true;
                var certificate = GenerateCertificate(random, subjectName, subjectKeyPair, serialNumber,
                                                      subjectAlternativeNames, issuerName, issuerKeyPair,
                                                      issuerSerialNumber, isCertificateAuthority,
                                                      usages);
                return ConvertCertificate(certificate, subjectKeyPair, random);
            }

            public static X509Certificate2 CreateSelfSignedCertificate(string subjectName, string[] subjectAlternativeNames, KeyPurposeID[] usages)
            {
                // It's self-signed, so these are the same.
                var issuerName = subjectName;

                var random = GetSecureRandom();
                var subjectKeyPair = GenerateKeyPair(random, 2048);

                // It's self-signed, so these are the same.
                var issuerKeyPair = subjectKeyPair;

                var serialNumber = GenerateSerialNumber(random);
                var issuerSerialNumber = serialNumber; // Self-signed, so it's the same serial number.

                const bool isCertificateAuthority = false;
                var certificate = GenerateCertificate(random, subjectName, subjectKeyPair, serialNumber,
                                                      subjectAlternativeNames, issuerName, issuerKeyPair,
                                                      issuerSerialNumber, isCertificateAuthority,
                                                      usages);
                return ConvertCertificate(certificate, subjectKeyPair, random);
            }

            public static SecureRandom GetSecureRandom()
            {
                // Since we're on Windows, we'll use the CryptoAPI one (on the assumption
                // that it might have access to better sources of entropy than the built-in
                // Bouncy Castle ones):
                var randomGenerator = new CryptoApiRandomGenerator();
                var random = new SecureRandom(randomGenerator);
                return random;
            }

            public static Org.BouncyCastle.X509.X509Certificate GenerateCertificate(SecureRandom random,
                                                               string subjectName,
                                                               AsymmetricCipherKeyPair subjectKeyPair,
                                                               BigInteger subjectSerialNumber,
                                                               string[] subjectAlternativeNames,
                                                               string issuerName,
                                                               AsymmetricCipherKeyPair issuerKeyPair,
                                                               BigInteger issuerSerialNumber,
                                                               bool isCertificateAuthority,
                                                               KeyPurposeID[] usages)
            {
                var certificateGenerator = new X509V3CertificateGenerator();

                certificateGenerator.SetSerialNumber(subjectSerialNumber);

                // Set the signature algorithm. This is used to generate the thumbprint which is then signed
                // with the issuer's private key. We'll use SHA-256, which is (currently) considered fairly strong.
                const string signatureAlgorithm = "SHA256WithRSA";
#pragma warning disable CS0618 // Type or member is obsolete
                certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);
#pragma warning restore CS0618 // Type or member is obsolete

                var issuerDN = new X509Name("CN=" + issuerName);
                certificateGenerator.SetIssuerDN(issuerDN);

                // Note: The subject can be omitted if you specify a subject alternative name (SAN).
                var subjectDN = new X509Name("CN=" + subjectName);
                certificateGenerator.SetSubjectDN(subjectDN);

                // Our certificate needs valid from/to values.
                var notBefore = DateTime.UtcNow.Date;
                var notAfter = notBefore.AddYears(2);

                certificateGenerator.SetNotBefore(notBefore);
                certificateGenerator.SetNotAfter(notAfter);

                // The subject's public key goes in the certificate.
                certificateGenerator.SetPublicKey(subjectKeyPair.Public);

                AddAuthorityKeyIdentifier(certificateGenerator, issuerDN, issuerKeyPair, issuerSerialNumber);
                AddSubjectKeyIdentifier(certificateGenerator, subjectKeyPair);
                AddBasicConstraints(certificateGenerator, isCertificateAuthority);

                if (usages != null && usages.Any())
                    AddExtendedKeyUsage(certificateGenerator, usages);

                if (subjectAlternativeNames != null && subjectAlternativeNames.Any())
                    AddSubjectAlternativeNames(certificateGenerator, subjectAlternativeNames);

                // The certificate is signed with the issuer's private key.
#pragma warning disable CS0618 // Type or member is obsolete
                var certificate = certificateGenerator.Generate(issuerKeyPair.Private, random);
#pragma warning restore CS0618 // Type or member is obsolete
                return certificate;
            }

            /// <summary>
            /// The certificate needs a serial number. This is used for revocation,
            /// and usually should be an incrementing index (which makes it easier to revoke a range of certificates).
            /// Since we don't have anywhere to store the incrementing index, we can just use a random number.
            /// </summary>
            /// <param name="random"></param>
            /// <returns></returns>
            public static BigInteger GenerateSerialNumber(SecureRandom random)
            {
                var serialNumber =
                    BigIntegers.CreateRandomInRange(
                        BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
                return serialNumber;
            }

            /// <summary>
            /// Generate a key pair.
            /// </summary>
            /// <param name="random">The random number generator.</param>
            /// <param name="strength">The key length in bits. For RSA, 2048 bits should be considered the minimum acceptable these days.</param>
            /// <returns></returns>
            public static AsymmetricCipherKeyPair GenerateKeyPair(SecureRandom random, int strength)
            {
                var keyGenerationParameters = new KeyGenerationParameters(random, strength);

                var keyPairGenerator = new RsaKeyPairGenerator();
                keyPairGenerator.Init(keyGenerationParameters);
                var subjectKeyPair = keyPairGenerator.GenerateKeyPair();
                return subjectKeyPair;
            }

            /// <summary>
            /// Add the Authority Key Identifier. According to http://www.alvestrand.no/objectid/2.5.29.35.html, this
            /// identifies the public key to be used to verify the signature on this certificate.
            /// In a certificate chain, this corresponds to the "Subject Key Identifier" on the *issuer* certificate.
            /// The Bouncy Castle documentation, at http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation,
            /// shows how to create this from the issuing certificate. Since we're creating a self-signed certificate, we have to do this slightly differently.
            /// </summary>
            /// <param name="certificateGenerator"></param>
            /// <param name="issuerDN"></param>
            /// <param name="issuerKeyPair"></param>
            /// <param name="issuerSerialNumber"></param>
            public static void AddAuthorityKeyIdentifier(X509V3CertificateGenerator certificateGenerator,
                                                          X509Name issuerDN,
                                                          AsymmetricCipherKeyPair issuerKeyPair,
                                                          BigInteger issuerSerialNumber)
            {
                var authorityKeyIdentifierExtension =
                    new AuthorityKeyIdentifier(
                        SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuerKeyPair.Public),
                        new GeneralNames(new GeneralName(issuerDN)),
                        issuerSerialNumber);
                certificateGenerator.AddExtension(
                    X509Extensions.AuthorityKeyIdentifier.Id, false, authorityKeyIdentifierExtension);
            }

            /// <summary>
            /// Add the "Subject Alternative Names" extension. Note that you have to repeat
            /// the value from the "Subject Name" property.
            /// </summary>
            /// <param name="certificateGenerator"></param>
            /// <param name="subjectAlternativeNames"></param>
            public static void AddSubjectAlternativeNames(X509V3CertificateGenerator certificateGenerator,
                                                           IEnumerable<string> subjectAlternativeNames)
            {
                var subjectAlternativeNamesExtension =
                    new DerSequence(
                        subjectAlternativeNames.Select(name => new GeneralName(GeneralName.DnsName, name))
                                               .ToArray<Asn1Encodable>());

                certificateGenerator.AddExtension(
                    X509Extensions.SubjectAlternativeName.Id, false, subjectAlternativeNamesExtension);
            }

            /// <summary>
            /// Add the "Extended Key Usage" extension, specifying (for example) "server authentication".
            /// </summary>
            /// <param name="certificateGenerator"></param>
            /// <param name="usages"></param>
            private static void AddExtendedKeyUsage(X509V3CertificateGenerator certificateGenerator, KeyPurposeID[] usages)
            {
                certificateGenerator.AddExtension(
                    X509Extensions.ExtendedKeyUsage.Id, false, new ExtendedKeyUsage(usages));
            }

            /// <summary>
            /// Add the "Basic Constraints" extension.
            /// </summary>
            /// <param name="certificateGenerator"></param>
            /// <param name="isCertificateAuthority"></param>
            public static void AddBasicConstraints(X509V3CertificateGenerator certificateGenerator,
                                                    bool isCertificateAuthority)
            {
                certificateGenerator.AddExtension(
                    X509Extensions.BasicConstraints.Id, true, new BasicConstraints(isCertificateAuthority));
            }

            /// <summary>
            /// Add the Subject Key Identifier.
            /// </summary>
            /// <param name="certificateGenerator"></param>
            /// <param name="subjectKeyPair"></param>
            public static void AddSubjectKeyIdentifier(X509V3CertificateGenerator certificateGenerator,
                                                        AsymmetricCipherKeyPair subjectKeyPair)
            {
                var subjectKeyIdentifierExtension =
                    new SubjectKeyIdentifier(
                        SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectKeyPair.Public));
                certificateGenerator.AddExtension(
                    X509Extensions.SubjectKeyIdentifier.Id, false, subjectKeyIdentifierExtension);
            }

            public static X509Certificate2 ConvertCertificate(Org.BouncyCastle.X509.X509Certificate certificate,
                                                               AsymmetricCipherKeyPair subjectKeyPair,
                                                               SecureRandom random)
            {
                // Now to convert the Bouncy Castle certificate to a .NET certificate.
                // See http://web.archive.org/web/20100504192226/http://www.fkollmann.de/v2/post/Creating-certificates-using-BouncyCastle.aspx
                // ...but, basically, we create a PKCS12 store (a .PFX file) in memory, and add the public and private key to that.
                var store = new Pkcs12Store();

                // What Bouncy Castle calls "alias" is the same as what Windows terms the "friendly name".
                string friendlyName = certificate.SubjectDN.ToString();

                // Add the certificate.
                var certificateEntry = new X509CertificateEntry(certificate);
                store.SetCertificateEntry(friendlyName, certificateEntry);

                // Add the private key.
                store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(subjectKeyPair.Private), new[] { certificateEntry });

                // Convert it to an X509Certificate2 object by saving/loading it from a MemoryStream.
                // It needs a password. Since we'll remove this later, it doesn't particularly matter what we use.
                const string password = "password";
                var stream = new MemoryStream();
                store.Save(stream, password.ToCharArray(), random);

                var convertedCertificate =
                    new X509Certificate2(stream.ToArray(),
                                         password,
                                         X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                return convertedCertificate;
            }

            public static void WriteCertificate(X509Certificate2 certificate, string outputFileName)
            {
                // This password is the one attached to the PFX file. Use 'null' for no password.
                const string password = "password";
                var bytes = certificate.Export(X509ContentType.Pfx, password);
                File.WriteAllBytes(outputFileName, bytes);
            }
        }

        public struct SslProtObj
        {
            public SslProtocols sslProt;
        }

        public VSslCertification(VLogger log, VConsole con, VDependencyWatcher vdw)
        {
            logger = log;
            console = con;
            self = this;
            vdw.AddCondition(() => { return UseCASign && !File.Exists("certs\\AHROOT.pfx"); }, new VLogger.LogObj()
            {
                ll = VLogger.LogLevel.warning,
                message = "CA Signing is enabled, but the root CA Cert is not found at its location"
            });
        }

        public void Init()
        {
            if (!Directory.Exists("certs")) Directory.CreateDirectory("certs");
        }

        public bool GetCert()
        {
            string toCheck = "";
            if (UseCASign) toCheck = "certs\\AHROOT.pfx";
            else toCheck = "certs\\general.xcer";
            if (!File.Exists(toCheck)) return false;
            X509Certificate2 c;
            if (toCheck.EndsWith(".xcer")) c = new X509Certificate2(toCheck);
            else c = new X509Certificate2(toCheck, "password");
            return true;
        }

        public X509Certificate2 GetCert(string hostName)
        {
            try
            {
                if (File.Exists("certs\\" + hostName + ".pfx") && UseCASign)
                {
                    return new X509Certificate2("certs\\" + hostName + ".pfx", "password");
                }
                else if (File.Exists("certs\\general.pfx") && !UseCASign)
                {
                    return new X509Certificate2("certs\\general.xcer");
                }
                else return null;
            }
            catch (Exception ex)
            {
                logger.Log("Failed to get the certificate:\r\n" + ex.ToString(), VLogger.LogLevel.error);
                return null;
            }
        }

        private void GenBatch(string mcertCommand)
        {
            string nl = Environment.NewLine;
            string batchFile = "@echo off" + nl + "cd \"" + Application.StartupPath + "\"" + nl;
            string dLetter = Application.StartupPath.Split(':')[0];
            batchFile += dLetter + ":" + nl;
            batchFile += mcertCommand + nl;
            batchFile += "echo Operation Completed!";
            File.Create("gencert.bat").Close();
            File.WriteAllText("gencert.bat", batchFile);
        }

        private bool IsAdmin()
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent(); //Get my identity
            var principal = new System.Security.Principal.WindowsPrincipal(identity); //Get my principal
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator); //Check if i'm an elevated process
        }

        public void BCGenerateCertificate(string hostName)
        {
            if (!File.Exists("certs\\AHROOT.pfx")) return;
            X509Certificate2 caCert = CertificateGenerator.LoadCertificate("certs\\AHROOT.pfx", "password");
            X509Certificate2 serverCert = CertificateGenerator.IssueCertificate(hostName, caCert, new string[] { hostName, "*." + hostName }, new KeyPurposeID[] {
                KeyPurposeID.IdKPServerAuth });

            CertificateGenerator.WriteCertificate(serverCert, "certs\\" + hostName + ".pfx");
        }

        public bool InstallToTrustedRoot()
        {
            const string caCertFile = "certs\\AHROOT.pfx";
            if (!File.Exists(caCertFile)) return false;
            X509Certificate2 caCert = CertificateGenerator.LoadCertificate(caCertFile, "password");
            try
            {
                X509Store certStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                certStore.Open(OpenFlags.ReadWrite);
                certStore.Add(caCert);
                certStore.Close();
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public bool GenerateCA(string commonName = "ah101CA")
        {
            if (!IsAdmin()) return false;
            X509Certificate2 caCert = CertificateGenerator.CreateCertificateAuthorityCertificate(commonName, null, null);
            CertificateGenerator.WriteCertificate(caCert, "certs\\AHROOT.pfx");
            return true;
        }

        public void GenerateSelfSigned(string commonName = "ah101Signed")
        {
            const string outputFile = "certs\\general.pfx";

            X509Certificate2 generalCert =
                CertificateGenerator.CreateSelfSignedCertificate(commonName, new string[] { "example.com" }, new KeyPurposeID[] { KeyPurposeID.IdKPServerAuth });
            CertificateGenerator.WriteCertificate(generalCert, outputFile);
        }

        public SslProtocols GetProtocols()
        {
            SslProtocols protChain = SslProt[0].sslProt;
            for (int i = 1; i < SslProt.Length; i++)
            {
                protChain = protChain | SslProt[i].sslProt;
            }

            return protChain;
        }

        public void SetProtocols(SslProtObj[] prots)
        {
            SslProt = prots;
        }

        public static string ProtocolToString()
        {
            string result = "";
            foreach (SslProtObj po in self.SslProt)
            {
                SslProtocols prot = po.sslProt;
                if (prot == SslProtocols.Default) result += "default,";
                else if (prot == SslProtocols.None) result += "none,";
                else if (prot == SslProtocols.Ssl2) result += "sslv2,";
                else if (prot == SslProtocols.Ssl3) result += "sslv3,";
                else if (prot == SslProtocols.Tls) result += "tls,";
                else if (prot == SslProtocols.Tls11) result += "tlsv11,";
                else result += "tlsv12,";
            }

            if (result == "") return null;
            else result = result.Substring(0, result.Length - 1);
            return result;
        }

        public static SslProtObj[] StringToProtocols(string input)
        {
            if (input == "" || input == null)
            {
                SslProtObj poDefault = new SslProtObj
                {
                    sslProt = SslProtocols.None
                };
                return new SslProtObj[] { poDefault };
            }

            if (!input.Contains(","))
            {
                input = input + ",";
            }

            List<SslProtObj> poList = new List<SslProtObj>();
            String[] prots = input.Split(',');
            foreach (string prot in prots)
            {
                if (prot == "") continue;
                SslProtObj po = new SslProtObj();
                if (prot == "default") po.sslProt = SslProtocols.Default;
                else if (prot == "none") po.sslProt = SslProtocols.None;
                else if (prot == "sslv2") po.sslProt = SslProtocols.Ssl2;
                else if (prot == "sslv3") po.sslProt = SslProtocols.Ssl3;
                else if (prot == "tls") po.sslProt = SslProtocols.Tls;
                else if (prot == "tlsv11") po.sslProt = SslProtocols.Tls11;
                else po.sslProt = SslProtocols.Tls12;
                poList.Add(po);
            }

            return poList.ToArray();
        }
    }

}
