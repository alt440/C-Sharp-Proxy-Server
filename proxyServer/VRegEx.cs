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
    public class VRegEx : IService, ISettings, IHelp, IDisposable
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
                _list.Clear();
                _list = null;
                logger = null;
            }

            disposed = true;
        }

        //IHelp Implementation

        private string _helpFile = "";

        public string HelpFile
        {
            get { return _helpFile; }
            set
            {
                if (File.Exists(value)) _helpFile = value;
            }
        }

        //ISettings Implementation

        public void LoadSettings(KeyValuePair<string, string> kvp)
        {
            string key = kvp.Key.ToLower();
            string value = kvp.Value.ToLower();

            if (key == "state") Started = (value == "true") ? true : false;
            if (key == "def_name")
            {
                if (!_list.ContainsKey(kvp.Value))
                {
                    RegList rl = new RegList
                    {
                        list = new List<Regex>()
                    };
                    _list.Add(kvp.Value, rl);
                }
            }
            if (key.StartsWith("reg_name_"))
            {
                string entryName = kvp.Key.Substring(9);
                string entryValue = kvp.Value;
                if (!_list.ContainsKey(entryName))
                {
                    RegList rl = new RegList
                    {
                        list = new List<Regex>()
                    };
                    _list.Add(entryName, rl);
                }

                RegList current = _list[entryName];
                Regex expression = new Regex(entryValue);
                current.list.Add(expression);
                _list[entryName] = current;
            }
        }

        public void WriteSettings(System.Xml.XmlWriter xml)
        {
            xml.WriteStartElement("settings_start");

            xml.WriteElementString("state", (Started) ? "true" : "false");

            foreach (KeyValuePair<string, RegList> kvp in _list)
            {
                string name = kvp.Key;
                xml.WriteElementString("def_name", name);

                foreach (Regex reg in kvp.Value.list)
                {
                    string value = reg.ToString();
                    xml.WriteElementString("reg_name_" + name, value);
                }
            }

            xml.WriteEndElement();
        }

        //IService Implementation

        private bool _started = true;
        private string _pRestore = "";
        private bool _selfInteractive = false;

        public bool SelfInteractive { get { return _selfInteractive; } set { _selfInteractive = value; } }
        public bool Started { get { return _started; } set { _started = value; } }
        public string PRestore { get { return _pRestore; } set { _pRestore = value; } }

        public void WarningMessage()
        {
            logger.Log("Regex Manager Service is not started!", VLogger.LogLevel.warning);
        }

        //Main RegEx Manager class

        struct RegList
        {
            public List<Regex> list;
        }

        private Dictionary<string, RegList> _list = new Dictionary<string, RegList>();
        private VLogger logger;

        public VRegEx(VLogger log)
        {
            logger = log;
        }

        public bool Add(string groupName)
        {
            if (_list.ContainsKey(groupName)) return false;
            RegList rl = new RegList
            {
                list = new List<Regex>()
            };
            _list.Add(groupName, rl);

            return true;
        }

        public bool AddExpression(string groupName, string expression)
        {
            if (!_list.ContainsKey(groupName)) return false;
            RegList rl = _list[groupName];
            Regex rx = new Regex(expression);
            rl.list.Add(rx);
            _list[groupName] = rl;

            return true;
        }

        public bool RunAnd(string input, string group)
        {
            if (!_list.ContainsKey(group)) return false;

            RegList rl = _list[group];

            foreach (Regex r in rl.list)
            {
                Match tResult = r.Match(input);
                bool tmp = tResult.Success;
                if (tmp == false) return false;
            }

            return true;
        }

        public bool RunOr(string input, string group)
        {
            if (!_list.ContainsKey(group)) return false;

            RegList rl = _list[group];

            foreach (Regex r in rl.list)
            {
                Match tResult = r.Match(input);
                bool tmp = tResult.Success;
                if (tmp == true) return true;
            }

            return false;
        }

        public bool Remove(string groupName)
        {
            if (!_list.ContainsKey(groupName)) return false;

            _list.Remove(groupName);

            return true;
        }

        public bool RemoveExpression(string groupName, string expression)
        {
            if (!_list.ContainsKey(groupName)) return false;

            RegList rl = _list[groupName];
            int index = 0;
            bool canRemove = false;

            foreach (Regex r in rl.list)
            {
                if (r.ToString() == expression)
                {
                    canRemove = true;
                    break;
                }

                index++;
            }

            if (canRemove) rl.list.RemoveAt(index);

            return true;
        }

        public bool IsRegexEmpty(string group)
        {
            if (group == null) return true;
            if (!_list.ContainsKey(group)) return true;
            RegList rl = _list[group];
            if (rl.list.Count <= 0) return true;
            else return false;
        }

        public string ListExpressions(string group)
        {
            string result = "";

            if (!_list.ContainsKey(group)) return null;

            RegList rl = _list[group];
            if (rl.list == null) return null;
            result = "==Start of Regular Expressions List==\r\n";
            result += "Count: " + rl.list.Count + "\r\n";

            foreach (Regex rx in rl.list)
            {
                result += rx.ToString() + "\r\n";
            }

            result += "==End of Regular Expressions List==\r\n";

            return result;
        }

        public string ListGroups()
        {
            string result = "";

            result = "==Start of RegEx group list==\r\n";
            result += "Count: " + _list.Keys.Count + "\r\n";

            foreach (string s in _list.Keys)
            {
                result += s + "\r\n";
            }

            result += "==End fo RegEx group list==\r\n";

            return result;
        }
    }

}
