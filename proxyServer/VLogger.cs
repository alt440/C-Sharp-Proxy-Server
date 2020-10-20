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
    public class VLogger : IFilter, ISettings, IHelp, IDisposable
    {
        //Implement IDisposable

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
                filterNames.Clear();
                filterNames = null;
                _vfmanager = null;
                console = null;
                File = null;
                pRestore = null;
            }

            disposed = true;
        }

        //Implement IHelp

        private string _helpFile = "";

        public string HelpFile
        {
            get { return _helpFile; }
            set
            {
                if (System.IO.File.Exists(value)) _helpFile = value;
            }
        }

        //Implement ISettigns

        public void LoadSettings(KeyValuePair<string, string> kvp)
        {
            string key = kvp.Key.ToLower();
            string value = kvp.Value.ToLower();

            if (key == "logger_file_state") printToFile = (value == "true") ? true : false;
            if (key == "logger_file_path") SetFile(kvp.Value);
            if (key == "logger_state") started = (value == "true") ? true : false;
            if (key == "logger_rest_rules") StringToRest(kvp.Value);
            if (key == "logger_bind_filter") PullBindInfo(kvp.Value);
        }

        public void WriteSettings(System.Xml.XmlWriter xml)
        {
            xml.WriteStartElement("settings_start");
            xml.WriteElementString("logger_file_state", (printToFile) ? "true" : "false");
            xml.WriteElementString("logger_file_path", File);
            xml.WriteElementString("logger_state", (started) ? "true" : "false");
            string loggerRules = RestToString();
            xml.WriteElementString("logger_rest_rules", loggerRules);
            xml.WriteElementString("logger_bind_filter", PushBindInfo());
            xml.WriteEndElement();
        }

        //Implement IFilter interface

        private Dictionary<string, object> filterNames = new Dictionary<string, object>();
        private VFilter _vfmanager;

        public Dictionary<string, object> FilterName
        {
            get { return filterNames; }
            set { filterNames = value; }
        }

        public VFilter Manager
        {
            get { return _vfmanager; }
            set { _vfmanager = value; }
        }

        public string PushBindInfo()
        {
            string info = "";

            foreach (KeyValuePair<string, object> kvp in filterNames)
            {
                string part2 = LogLevelToString(((LogLevel)kvp.Value));
                info += kvp.Key + ":" + part2 + ";";
            }

            if (info.Length > 0) info = info.Substring(0, info.Length - 1);

            return info;
        }

        public void PullBindInfo(string info)
        {
            if (info == "") return;
            String[] kvp = info.Split(';');
            foreach (String pairs in kvp)
            {
                string[] kvp2 = pairs.Split(':');
                LogLevel level = StringToLogLevel(kvp2[1]);
                string name = kvp2[0];
                filterNames.Add(name, level);
            }
        }

        public bool BindFilter(string validFilterName, object input)
        {
            LogLevel op = (LogLevel)input;
            if (op != LogLevel.request && op != LogLevel.response) return false;
            filterNames.Add(validFilterName, op);
            return true;
        }

        public bool SearchFilter(string sMethod, object searchParam, string input)
        {
            LogLevel p = (LogLevel)searchParam;
            string targetFilterName = "";
            foreach (KeyValuePair<string, object> pair in filterNames)
            {
                LogLevel comp = (LogLevel)pair.Value;
                if (comp == p)
                {
                    targetFilterName = pair.Key;
                    break;
                }
            }

            if (targetFilterName == "")
            {
                return true; // if target filter is not found output the text, perhaps there is no filter for a specific object
            }

            if (sMethod == "and")
            {
                return Manager.RunAllCompareAnd(targetFilterName, input);
            }
            else if (sMethod == "or")
            {
                return Manager.RunAllCompareOr(targetFilterName, input);
            }
            else
            {
                console.WriteLine("[ERROR] Invalid SearchFilter option sMethod", console.GetIntercativeGroup());
                return true;
            }
        }

        public bool UnBindFilter(string validFilterName)
        {
            if (!FilterName.ContainsKey(validFilterName)) return false;
            FilterName.Remove(validFilterName);
            return true;
        }

        public void BindList()
        {
            WriteLine("=========Start Of bind list=========");
            foreach (KeyValuePair<string, object> kvp in filterNames)
            {
                LogLevel ll = (LogLevel)kvp.Value;
                WriteLine(kvp.Key + ":\t" + LogLevelToString(ll));
            }
            WriteLine("==========End Of bind list==========");
        }

        public void SetManager(VFilter fman)
        {
            Manager = fman;
        }

        //Main logger class

        VConsole console;
        bool printRequest = false;
        bool printResponse = false;
        bool printWarning = false;
        bool printError = false;
        bool printService = false;
        public bool printToFile = true;
        public bool started = false;
        public string File { get; private set; } = "";
        public string pRestore = "";
        public bool selfInteractive = false;

        public enum LogLevel : int
        {
            information = 0,
            warning = 1,
            error = 2,
            service = 3,
            request = 4,
            response = 5,
            unknown = 6
        }

        public struct LogObj
        {
            public string message;
            public LogLevel ll;
            public Request r;
            public Response resp;
        }

        public VLogger(VConsole con)
        {
            console = con;
        }

        public void SetupLogLevel(bool err, bool war, bool srv, bool req, bool resp)
        {
            printError = err;
            printWarning = war;
            printService = srv;
            printRequest = req;
            printResponse = resp;
        }

        public void StringToRest(string rest)
        {
            printError = false;
            printWarning = false;
            printService = false;
            printRequest = false;
            printResponse = false;
            String[] rst = rest.Split(',');
            foreach (string r in rst)
            {
                if (r == "e") printError = true;
                if (r == "w") printWarning = true;
                if (r == "s") printService = true;
                if (r == "rq") printRequest = true;
                if (r == "rs") printResponse = true;
            }
        }

        public string RestToString()
        {
            string list = "";
            if (printError) list += "e,";
            if (printWarning) list += "w,";
            if (printService) list += "s,";
            if (printRequest) list += "rq,";
            if (printResponse) list += "rs,";
            list = list.Substring(0, list.Length - 1);
            return list;
        }

        public void SetFile(string filename)
        {
            if (filename == "") return;
            string logDir = Application.StartupPath + "\\Logs";
            string logFile = logDir + "\\" + filename;
            if (!Directory.Exists(logDir)) Directory.CreateDirectory(logDir);
            if (!System.IO.File.Exists(logFile))
            {
                System.IO.File.Create(logFile).Close();
            }

            File = logFile;
        }

        public void WriteLine(string text)
        {
            if (selfInteractive) console.WriteLine(text, "ig.logger");
            else console.WriteLine(text, console.GetIntercativeGroup());
        }

        public void WriteFile(string text)
        {
            if (System.IO.File.Exists(File) && printToFile && started)
            {
                string prev = System.IO.File.ReadAllText(File);
                string next = prev + Environment.NewLine + text;
                System.IO.File.WriteAllText(File, next);
            }
        }

        public void Log(string text, LogLevel level, Request r = null, Response re = null)
        {
            if (!started)
            {
                WriteLine(text);
                return;
            }

            string data = "";

            if (level == LogLevel.error)
            {
                data = "[ERROR] " + text;

                bool sfResult = SearchFilter("and", LogLevel.error, data);

                if (printError && sfResult)
                {
                    WriteLine(data);
                    WriteFile(data);
                }
            }

            if (level == LogLevel.warning)
            {
                data = "[WARNING] " + text;

                bool sfResult = SearchFilter("and", LogLevel.warning, data);

                if (printWarning && sfResult)
                {
                    WriteLine(data);
                    WriteFile(data);
                }
            }

            if (level == LogLevel.service)
            {
                data = "[SERVICE] " + text;

                bool sfResult = SearchFilter("and", LogLevel.service, data);

                if (printService && sfResult)
                {
                    WriteLine(data);
                    WriteFile(data);
                }
            }

            if (level == LogLevel.request)
            {
                if (r == null)
                {
                    data = "[REQUEST] " + text;
                }
                else
                {
                    data = "[REQUEST: " + r.method + "] ";
                    text = text.Replace("<method>", r.method);
                    text = text.Replace("<target>", r.target);
                    data += text;
                }

                bool sfResult = SearchFilter("and", LogLevel.request, data);

                if (printRequest && sfResult)
                {
                    WriteLine(data);
                    WriteFile(data);
                }
            }

            if (level == LogLevel.response)
            {
                if (re == null)
                {
                    data = "[RESPONSE] " + text;
                }
                else
                {
                    data = "[RESPONSE: " + re.statusCode + " " + re.httpMessage + "] ";
                    text = text.Replace("<code>", re.statusCode.ToString());
                    text = text.Replace("<version>", re.version);
                    text = text.Replace("<message>", re.httpMessage);
                    data += text;
                }

                bool sfResult = SearchFilter("and", LogLevel.response, data);

                if (printResponse && sfResult)
                {
                    WriteLine(data);
                    WriteFile(data);
                }
            }

            if (level == LogLevel.information)
            {
                data = text;
                bool sfResult = SearchFilter("and", LogLevel.information, data);
                if (!sfResult) return;
                WriteLine(data);
                WriteFile(data);
            }
        }

        //LogLevel converters

        public static LogLevel StringToLogLevel(string input)
        {
            input = input.ToLower();
            if (input == "error") return LogLevel.error;
            if (input == "warning") return LogLevel.warning;
            if (input == "service") return LogLevel.service;
            if (input == "request") return LogLevel.request;
            if (input == "response") return LogLevel.response;
            if (input == "information") return LogLevel.information;
            return LogLevel.unknown;
        }

        public static string LogLevelToString(LogLevel input)
        {
            if (input == LogLevel.error) return "error";
            if (input == LogLevel.warning) return "warning";
            if (input == LogLevel.service) return "service";
            if (input == LogLevel.request) return "request";
            if (input == LogLevel.response) return "response";
            if (input == LogLevel.information) return "information";
            return null;
        }
    }

}
