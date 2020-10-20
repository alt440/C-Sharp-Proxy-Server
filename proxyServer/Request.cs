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
    public class Request : IDisposable
    {
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
                full = null;
                target = null;
                method = null;
                version = null;
                htmlBody = null;
                headers.Clear();
                headers.Dispose();
                headers = null;
            }

            disposed = true;
        }

        public string full;
        public bool bogus = false;
        public bool notEnded = false;
        public string target;
        public string method;
        public string version;
        public string htmlBody;
        public VDictionary headers = new VDictionary();

        public Request(string req, bool sslMode = false)
        {
            full = req;
            Serialize(sslMode);
        }

        public void Serialize(bool fromSslStream = false)
        {
            if (full == "")
            {
                bogus = true;
                return;
            }
            if (!full.EndsWith("\r\n\r\n") && fromSslStream) notEnded = true; //setting only when requests are marked to allow normal (not MITM) https packets even if they are not ending with \r\n\r\n

            try
            {
                string infoLine = full.Split('\n')[0].Replace("\r", String.Empty);
                string[] iParts = infoLine.Split(' ');
                method = iParts[0];
                target = iParts[1];
                version = iParts[2];
                headers = new VDictionary();
                string[] data = full.Split('\n');
                bool isBody = false;
                string nl = Environment.NewLine;
                for (int i = 1; i < data.Length; i++)
                {
                    string line = data[i].Replace("\r", String.Empty);
                    if (line == "")
                    {
                        isBody = true;
                        continue;
                    }

                    if (!isBody)
                    {
                        //Add headers
                        string hName = line.Substring(0, line.IndexOf(':'));
                        string hValue = line.Substring(line.IndexOf(':') + 2, line.Length - line.IndexOf(':') - 2);
                        headers.Add(hName, hValue);
                    }
                    else
                    {
                        if ((i + 1) < data.Length) htmlBody += line + nl;
                        else if ((i + 1) == data.Length) htmlBody += line;
                    }
                }

                //Add ssl packet filter
                if (!version.Contains("HTTP")) bogus = true;
            }
            catch (Exception)
            {
                bogus = true;
            }
        }

        public string Deserialize()
        {
            string nl = Environment.NewLine;
            string request = method + " " + target + " " + version + nl;
            for (int i = 0; i < headers.Count; i++)
            {
                string hName = headers.Keys.ToArray()[i];
                string hValue = headers.Values.ToArray()[i];
                string line = hName + ": " + hValue;
                request += line + nl;
            }
            request += nl;
            request += htmlBody;
            return request;
        }
    }

}
