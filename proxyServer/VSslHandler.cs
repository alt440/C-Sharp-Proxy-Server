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
    public class VSslHandler : IDisposable
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
                ctx = null;
                certman = null;
                Close();
                _ssl = null;
                Array.Clear(buffer, 0, buffer.Length);
                buffer = null;
                console = null;
            }

            disposed = true;
        }

        private Form1 ctx;
        private VSslCertification certman;
        private SslStream _ssl;
        private byte[] buffer = new byte[2048];
        private VConsole console;

        public VSslHandler(Form1 context, VConsole con)
        {
            ctx = context;
            console = con;
        }

        public enum Error
        {
            CertificateManagerNotAvailable,
            Success,
            CertAutoGenerationFailed,
            CertRetrieveFailed,
            SslProtocolRetrieveFailed,
            SslServerAuthFailed,
            SslStreamCantWrite,
            SslStreamWriteFailed,
            SslStreamDisposed
        }

        public Error InitSslStream(NetworkStream ns, string targetHost)
        {
            SslStream ssl = new SslStream(ns);
            certman = ctx.CertMod;
            if (certman == null || !certman.Started) return Error.CertificateManagerNotAvailable;
            X509Certificate2 cert = certman.GetCert(targetHost);
            if (cert == null) certman.BCGenerateCertificate(targetHost);
            cert = certman.GetCert(targetHost);
            if (cert == null) return Error.CertRetrieveFailed;
            SslProtocols sp = certman.GetProtocols();
            if (sp == SslProtocols.None) return Error.SslProtocolRetrieveFailed;
            try
            {
                ssl.AuthenticateAsServer(cert, false, sp, true);
                _ssl = ssl;
                return Error.Success;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                ctx.LogMod.Log("SSL Server Init Error:\r\n" + ex.ToString(), VLogger.LogLevel.error);
                return Error.SslServerAuthFailed;
            }
        }

        public void InitAsyncRead()
        {
            ReadObj r = new ReadObj
            {
                full = "",
                r = null,
                requestHandled = false
            };
            _ssl.BeginRead(buffer, 0, buffer.Length, new AsyncCallback(ReadFromStream), r);
        }

        public Error WriteSslStream(byte[] data)
        {
            if (_ssl == null) return Error.SslStreamDisposed;
            if (!_ssl.CanWrite) return Error.SslStreamCantWrite;
            try { _ssl.Write(data, 0, data.Length); }
            catch (Exception)
            {
                return Error.SslStreamWriteFailed;
            }

            return Error.Success;
        }

        public void FlushSslStream()
        {
            _ssl.Flush();
        }

        public Error Close()
        {
            if (_ssl == null) return Error.SslStreamDisposed;
            _ssl.Close();
            _ssl.Dispose();
            return Error.Success;
        }

        struct ReadObj
        {
            public string full;
            public Request r;
            public bool requestHandled;
        }

        private void ReadFromStream(IAsyncResult ar)
        {
            ReadObj ro = (ReadObj)ar.AsyncState;
            Request r = ro.r;
            int bytesRead = 0;
            try { bytesRead = _ssl.EndRead(ar); }
            catch (Exception) { return; }
            byte[] read = new byte[bytesRead];
            Array.Copy(buffer, read, bytesRead);
            string text = Encoding.ASCII.GetString(read);

            if (bytesRead > 0)
            {
                if (r == null)
                {
                    r = new Request(text, true);
                }

                if (r.notEnded)
                {
                    if (ro.full == "") ro.full = text;
                    else
                    {
                        ro.full += text;
                        r = new Request(ro.full, true);
                    }
                }

                if (!r.notEnded && !r.bogus)
                {
                    if (ctx.mitmHttp.started)
                    {
                        ctx.mitmHttp.DumpRequest(r);
                    }

                    string requestString = r.Deserialize();

                    Tunnel.Send(requestString, Tunnel.Mode.HTTPs, ctx, r, null, this);
                    ro.full = "";
                    ro.requestHandled = true;
                }
            }

            Array.Clear(buffer, 0, buffer.Length);
            if (!ro.requestHandled) ro.r = r;
            else
            {
                ro.r = null;
                ro.requestHandled = false;
            }
            try { _ssl.BeginRead(buffer, 0, buffer.Length, new AsyncCallback(ReadFromStream), ro); }
            catch (Exception ex)
            {
                //ctx.LogMod.Log("Ssl stream error MITM\r\n" + ex.Message, VLogger.LogLevel.error);
                Console.WriteLine("St: " + ex.StackTrace);
            }
        }
    }

}
