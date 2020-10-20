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
    class HelperMethods
    {
        /*public bool isStarted = false;
        public int pendingConnectionLimit = 3;
        public string ip = "localhost";
        public int port = 8080;
        public ProxyServer server;
        public VConsole ConMod;
        private VPin PinMod;
        private VSettings SetMod;
        public VLogger LogMod;
        public VFilter vf;
        public VMitm mitmHttp;
        public VSslCertification CertMod;
        public VDump DumpMod;
        public VDependencyWatcher VdwMod;
        public VRegEx RegMod;
        public VInject InjectMod;
        public VHelp HelpMod;
        public Server _ipcServer;
        public Form1 form1;*/

        public string GetPayload(string payload)
        {
            bool isFile = false;
            if (payload.Length > 3)
            {
                Regex file = new Regex("[a-zA-Z]:\\\\");
                isFile = file.Match(payload).Success;
                if (!isFile)
                {
                    string temp = "";
                    temp = Application.StartupPath + "\\" + payload;
                    isFile = file.Match(temp).Success;
                    if (isFile && File.Exists(temp)) payload = temp;
                }
            }

            if (isFile && File.Exists(payload)) return File.ReadAllText(payload);
            else return payload;
        }

        public VLogger.LogObj CreateLog(string text, VLogger.LogLevel ll)
        {
            VLogger.LogObj lo = new VLogger.LogObj
            {
                message = text,
                ll = ll,
                r = null,
                resp = null
            };
            return lo;
        }

        public ProxyServer CreateServer(ProxyServer server, string ip, int port, int pendingConnectionLimit, VConsole ConMod, Form1 form1)
        {
            if (server == null) server = new ProxyServer(ip, port, pendingConnectionLimit, ConMod, form1);
            return server;
        }

        public string[] Ie2sa(IEnumerable<string> input)
        {
            List<string> s = new List<string>();
            foreach (string str in input)
            {
                s.Add(str);
            }

            return s.ToArray();
        }

        public VFilter.Operation S2op(string input)
        {
            input = input.ToLower();
            if (input == "startswith") return VFilter.Operation.StartsWith;
            if (input == "contains") return VFilter.Operation.Contains;
            if (input == "equals") return VFilter.Operation.Equals;
            if (input == "notequals") return VFilter.Operation.NotEquals;

            return VFilter.Operation.Undefined;
        }

        public List<Socket> ListCopy(List<Socket> input)
        {
            List<Socket> result = new List<Socket>();

            foreach (Socket item in input)
            {
                result.Add(item);
            }

            return result;
        }

        public bool IsByteArrayEmpty(byte[] array)
        {
            foreach (byte b in array)
            {
                if (b != 0) return false;
            }

            return true;
        }

        public bool PortVerification(int port)
        {
            if (port < 65535)
                return true;
            return false;
        }

        public bool IpVerification(string input)
        {
            if (input == "any" || input == "loopback" || input == "localhost")
            {
                return true;
            }
            else if (input.Contains("."))
            {
                string[] parts = input.Split('.');
                if (parts.Length == 4)
                {
                    foreach (string part in parts)
                    {
                        for (int i = 0; i < part.Length; i++)
                        {
                            if (!char.IsNumber(part[i])) return false;
                        }
                    }

                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        public void FinalExit(Server _ipcServer, ProxyServer server, VLogger LogMod, 
            VDependencyWatcher VdwMod, VSettings SetMod, VInject InjectMod, VRegEx RegMod,
            VMitm mitmHttp, VDump DumpMod, VSslCertification CertMod, VConsole ConMod, 
            VPin PinMod, VFilter vf, bool isStarted)
        {
            if (_ipcServer != null) _ipcServer.CloseAllPipes();

            LogMod.Log("IPC Server Shutdown OK", VLogger.LogLevel.service);

            if (server != null)
            {
                server.StopServer();
                server.Dispose();
                server = null;
            }

            LogMod.Log("Server Shutdown OK", VLogger.LogLevel.service);

            VdwMod.Dispose();
            VdwMod = null;
            LogMod.Log("Dependency Watcher Shutdown OK", VLogger.LogLevel.service);
            SetMod.Dispose();
            SetMod = null;
            LogMod.Log("Settings Shutdown OK", VLogger.LogLevel.service);
            InjectMod.Dispose();
            InjectMod = null;
            LogMod.Log("Injection Shutdown OK", VLogger.LogLevel.service);
            RegMod.Dispose();
            RegMod = null;
            LogMod.Log("Filter.Regex Shutdown OK", VLogger.LogLevel.service);
            mitmHttp.Dispose();
            mitmHttp = null;
            LogMod.Log("MITM Shutdown OK", VLogger.LogLevel.service);
            DumpMod.Dispose();
            DumpMod = null;
            LogMod.Log("Data Dump Shutdown OK", VLogger.LogLevel.service);
            CertMod.Dispose();
            CertMod = null;
            LogMod.Log("Certification Manager Shutdown OK", VLogger.LogLevel.service);
            LogMod.Dispose();
            LogMod = null;
            ConMod.Debug("Logger Shutdown OK");
            vf.Dispose();
            vf = null;
            ConMod.Debug("Filter.Filters Shutdown OK");
            PinMod.Dispose();
            PinMod = null;
            ConMod.WriteLine("Pin Manager Shutdown OK");
            ConMod.WriteLine("Shutting down console and closing process");
            ConMod.Dispose();
            ConMod = null;
            isStarted = false;
            Environment.Exit(0); //app terminated. No need to return objects.
        }

        public bool S2b(string text, bool defaultSecureValue, VConsole ConMod)
        {
            bool result = false;
            String[] positiveKw = { "enable", "on", "yes", "start", "up" };
            String[] negativeKw = { "disable", "off", "no", "stop", "down" };
            text = text.ToLower();
            text = text.Trim();
            if (positiveKw.Contains(text)) result = true;
            if (negativeKw.Contains(text)) result = false;
            if (!positiveKw.Contains(text) && !negativeKw.Contains(text))
            {
                string def;
                def = (defaultSecureValue) ? "Enabled" : "Disabled";
                result = defaultSecureValue;
                ConMod.WriteLine("[WARNING] Invalid Input!\r\n\t    Setting to the default value: " + def);
            }

            return result;
        }

        public void ServerNotStarted(VConsole ConMod)
        {
            ConMod.WriteLine("[WARNING] Server is not started");
        }

        public void ServiceNotStarted(VConsole ConMod)
        {
            ConMod.WriteLine("[WARNING] Service is not started");
        }

        public bool IsInteger(string value, VConsole ConMod)
        {
            bool result = true;

            for (int i = 0; i < value.Length; i++)
            {
                if (!char.IsNumber(value[i]))
                {
                    result = false;
                    break;
                }
            }

            if (!result)
            {
                ConMod.WriteLine("[ERROR] Input is not a valid number");
            }

            return result;
        }

        public bool IsFloat(string input, VConsole ConMod)
        {
            bool result = true;
            char decimalSeparator = Convert.ToChar(System.Globalization.CultureInfo.CurrentCulture.NumberFormat.NumberDecimalSeparator);

            for (int i = 0; i < input.Length; i++)
            {
                if (!char.IsNumber(input[i]) && input[i] != decimalSeparator)
                {
                    result = false;
                    break;
                }
            }

            if (!result)
            {
                ConMod.WriteLine("[ERROR] Input is not a valid decimal number");
            }

            return result;
        }

        public System.Drawing.Color S2c(string colorName)
        {
            System.Drawing.Color result = System.Drawing.Color.Empty;
            colorName = colorName.ToLower();

            switch (colorName)
            {
                case "black":
                    result = System.Drawing.Color.Black;
                    break;

                case "white":
                    result = System.Drawing.Color.White;
                    break;

                case "green":
                    result = System.Drawing.Color.Lime;
                    break;

                case "blue":
                    result = System.Drawing.Color.Blue;
                    break;

                case "aqua":
                    result = System.Drawing.Color.Aqua;
                    break;

                case "gray":
                    result = System.Drawing.Color.Gray;
                    break;

                case "purple":
                    result = System.Drawing.Color.Purple;
                    break;

                case "yellow":
                    result = System.Drawing.Color.Gold;
                    break;
            }

            return result;
        }

        public string C2s(System.Drawing.Color color)
        {
            string result = "";

            if (color == System.Drawing.Color.Black) result = "black";
            else if (color == System.Drawing.Color.White) result = "white";
            else if (color == System.Drawing.Color.Gold) result = "yellow";
            else if (color == System.Drawing.Color.Lime) result = "green";
            else if (color == System.Drawing.Color.Aqua) result = "aqua";
            else if (color == System.Drawing.Color.Blue) result = "blue";
            else if (color == System.Drawing.Color.Purple) result = "purple";
            else if (color == System.Drawing.Color.Gray) result = "gray";

            return result;
        }
    }
}
