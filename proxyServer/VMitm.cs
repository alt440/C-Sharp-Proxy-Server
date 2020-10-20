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
    public class VMitm : ISettings, IHelp, IDisposable
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
                _libstateCache = 0;
                _lidstateCache = 0;
                _liistateCache = 0;
                pRestore = null;
                ctx = null;
                vf = null;
                dump = null;
                logger = null;
                vi = null;
                dw = null;
                console = null;
                Array.Clear(dumpServices, 0, dumpServices.Length);
                Array.Clear(blockServices, 0, blockServices.Length);
                Array.Clear(injectServices, 0, injectServices.Length);
                Array.Clear(srvFullName, 0, srvFullName.Length);
                Array.Clear(defs, 0, defs.Length);
                bState = null;
                dState = null;
                iState = null;
                dumpServices = null;
                injectServices = null;
                blockServices = null;
                defs = null;
                srvFullName = null;
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

        //ISettigs Implementation

        private int _libstateCache = 0;
        private int _lidstateCache = 0;
        private int _liistateCache = 0;

        public void LoadSettings(KeyValuePair<string, string> kvp)
        {
            string key = kvp.Key.ToLower();
            string value = kvp.Value.ToLower();

            if (key == "state") started = (value == "true") ? true : false;
            if (key == "b_inc_state")
            {
                bState[_libstateCache] = (value == "true") ? true : false;
                _libstateCache++;
            }
            if (key == "d_inc_state")
            {
                dState[_lidstateCache] = (value == "true") ? true : false;
                _lidstateCache++;
            }
            if (key == "i_inc_state")
            {
                iState[_liistateCache] = (value == "true") ? true : false;
                _liistateCache++;
            }
        }

        public void WriteSettings(System.Xml.XmlWriter xml)
        {
            xml.WriteStartElement("settings_start");
            xml.WriteElementString("state", (started) ? "true" : "false");
            //Add the states of the blocking services
            foreach (bool b in bState)
            {
                xml.WriteElementString("b_inc_state", (b) ? "true" : "false");
            }

            //Add the states of the dumping services
            foreach (bool d in dState)
            {
                xml.WriteElementString("d_inc_state", (d) ? "true" : "false");
            }

            foreach (bool i in iState)
            {
                xml.WriteElementString("i_inc_state", (i) ? "true" : "false");
            }

            xml.WriteEndElement();
        }

        //Main MITM class

        public bool started = true;
        public bool selfInteractive = false;
        public string pRestore = "";
        private Form1 ctx;
        private VFilter vf;
        private VDump dump;
        private VLogger logger;
        private VConsole console;
        private VDependencyWatcher dw;
        private VInject vi;
        String[] blockServices = { "mitm_hostblock", "mitm_ipblock", "mitm_bodyblock" };
        String[] dumpServices = { "mitm_cookie_dump", "mitm_getparams_dump", "mitm_postparams_dump", "mitm_url_dump", "mitm_setcookie_dump" };
        String[] injectServices = { "mitm_inject_core", "mitm_inject_auto", "mitm_inject_match", "mitm_inject_media" };
        List<bool> dState = new List<bool>();
        List<bool> bState = new List<bool>();
        List<bool> iState = new List<bool>();
        String[] srvFullName = { "Host Blocking", "IP Blocking", "Body Text based Blocking" };
        String[] defs = { "Blocks a server based on the requested hostname", "Blocks a server based on the resolved IPv4 Address", "Block a server based on the response body",
        "Dump Cookie headers sent by the client", "Dump GET request parameters", "Dump POST request Parameters", "Dump requested URLs", "Dump server response set-cookie headers",
        "Injection Core / Inject manager", "Injects the payload automatically to the response body", "Injects the payload based on a line-by-line matching to the response body",
        "Replaces media files based on the original URL"};

        public enum BlockServices : int
        {
            Host = 0,
            IP = 1,
            Body = 2,
            Undefined = -1
        }

        public enum DumpServices : int
        {
            Cookie = 0,
            GetParameters = 1,
            PostParameters = 2,
            Url = 3,
            SetCookie = 4,
            Undefined = -1
        }

        public enum InjectServices
        {
            Core = 0,
            AutoInjection = 1,
            MatchInjection = 2,
            MediaInjection = 3,
            Undefined = -1
        }

        public VMitm(Form1 context, VConsole con)
        {
            ctx = context;
            console = con;
            for (int i = 0; i < dumpServices.Length; i++)
            {
                dState.Add(false);
            }

            for (int i = 0; i < blockServices.Length; i++)
            {
                bState.Add(false);
            }

            for (int i = 0; i < injectServices.Length; i++)
            {
                iState.Add(false);
            }

            dw = ctx.VdwMod;
            dw.AddCondition(() => !IsAllOfflineD() && !dump.Started, ctx.CreateLog("One or more dump service is active, but Dump Manager is not enabled", VLogger.LogLevel.warning));
        }

        /// <summary>
        /// Create all MITM related filters what you can configure by typing filter_manager and then use the setup command
        /// </summary>

        public void CreateFilters()
        {
            foreach (string s in blockServices)
            {
                string aFilter = s + "_white";
                string bFilter = s + "_black";
                vf.DestroyFilter(aFilter);
                vf.DestroyFilter(bFilter);
                vf.CreateFilter(aFilter);
                vf.CreateFilter(bFilter);
            }
        }

        /// <summary>
        /// Create all MITM related dumps (you can configure them in the dump_manager menu)
        /// </summary>

        public void CreateDumps()
        {
            if (dump != null && dump.Started)
            {
                if (dump.Dir == "") dump.DefineDirectory(Application.StartupPath + "\\dumps");
                dump.AddFile("parameter_dump.txt", "mitm_parameter_store", false);
                dump.AddFile("cookie_dump.txt", "mitm_cookie_store", false);
                dump.AddFile("url_dump.txt", "mitm_url_store", false);
            }
            else
            {
                logger.Log("Dump Manager is not available!", VLogger.LogLevel.error);
            }
        }

        /// <summary>
        /// Create All MITM related injects (you can configure them in mitm/inject_manager)
        /// </summary>

        public void CreateInjects()
        {
            if (vi != null)
            {
                VRegEx r = vi.Rxmanager;
                r.Add("mitm_inject_match_and");
                r.Add("mitm_inject_macth_or");
                vf.CreateFilter("mitm_inject_match_and");
                vf.CreateFilter("mitm_inject_match_or");
            }
        }

        /// <summary>
        /// Check for filter related errors
        /// </summary>
        /// <returns>String Array of error messages</returns>

        public String[] CheckBlockers()
        {
            List<string> errors = new List<string>();
            int loopIndex = 0;

            foreach (string s in blockServices)
            {
                //Black - White list related issues
                bool hostb = vf.IsFilterEmpty(s + "_black");
                bool hostw = vf.IsFilterEmpty(s + "_white");
                if (!hostb && !hostw) errors.Add("Both black & white list contains values for " + srvFullName[loopIndex] + " function, clear one list");
                if ((!hostb || !hostw) && !bState[loopIndex]) errors.Add("W: " + srvFullName[loopIndex] + " service filters are setup, but the service is turned off");
                loopIndex++;
            }

            return errors.ToArray();
        }

        /// <summary>
        /// Check's for dumper related errors
        /// </summary>
        /// <returns>String array of error messages</returns>

        public String[] CheckDumpers()
        {
            List<string> errors = new List<string>();
            if (dump == null || !dump.Started) errors.Add("Dump manager service is not available");
            if ((CheckServiceState(DumpServices.Cookie) || CheckServiceState(DumpServices.SetCookie)) && !dump.CheckFileByFriendlyName("mitm_cookie_store"))
                errors.Add("W: Dumpers set to dump cookies, but the store file doesn't exists, or it's not loaded to Dump manager");
            if ((CheckServiceState(DumpServices.GetParameters) || CheckServiceState(DumpServices.PostParameters)) && !dump.CheckFileByFriendlyName("mitm_parameter_store"))
                errors.Add("W: Dumpers set to dump parameters, but the store file doesn't exists, or it's not loaded to Dump manager");
            if (CheckServiceState(DumpServices.Url) && !dump.CheckFileByFriendlyName("mitm_url_store"))
                errors.Add("W: Dumpers set to dump urls, but the store file doesn't exists, or it's not loaded to Dump manager");

            return errors.ToArray();
        }

        /// <summary>
        /// Check's if a host need's to be blocked based on HostName
        /// </summary>
        /// <param name="httpRequest">The current Request object</param>
        /// <returns>True if host need's to be blocked</returns>

        public bool CheckHost(Request httpRequest)
        {
            string host = httpRequest.headers["Host"];
            bool serviceState = CheckServiceState(BlockServices.Host);
            if (!serviceState) return false;
            bool result = false;
            if (vf.IsFilterEmpty("mitm_hostblock_white")) result = vf.RunAllCompareOr("mitm_hostblock_black", host);
            else result = !vf.RunAllCompareOr("mitm_hostblock_white", host); //revert the value, because we don't want to block whitelisted hosts
            return result;
        }

        /// <summary>
        /// Check's if a server need's to be blocked based on IPv4 address
        /// </summary>
        /// <param name="ipAddress">The ip address of the target server</param>
        /// <returns>True if the server need's to be blocked</returns>

        public bool CheckIP(string ipAddress)
        {
            bool serviceState = CheckServiceState(BlockServices.IP);
            if (!serviceState) return false;
            bool result = false;
            if (vf.IsFilterEmpty("mitm_ipblock_white")) result = vf.RunAllCompareOr("mitm_ipblock_black", ipAddress);
            else result = !vf.RunAllCompareOr("mitm_ipblock_white", ipAddress); //revert the value, because we don't want to block whitelisted hosts
            return result;
        }

        /// <summary>
        /// Check's if a page need's to be blocked based on the text of the response body
        /// </summary>
        /// <param name="bodyText">The body text of a response object</param>
        /// <returns>True if page need's to be blocked</returns>

        public bool CheckBody(string bodyText)
        {
            bool serviceState = CheckServiceState(BlockServices.Body);
            if (!serviceState) return false;
            bool result = false;
            if (vf.IsFilterEmpty("mitm_bodyblock_white")) result = vf.RunAllCompareOr("mitm_bodyblock_black", bodyText);
            else result = !vf.RunAllCompareOr("mitm_bodyblock_white", bodyText); //revert the value, because we don't want to block whitelisted hosts
            return result;
        }

        /// <summary>
        /// Dump all data selected based on a Request object using VDump class
        /// </summary>
        /// <param name="r">The current request object</param>

        public void DumpRequest(Request r)
        {
            if (!IsAllOfflineD())
            {
                string fullParameterDump = "";
                string fullCookieDump = "";
                string fullUrlDump = "";
                bool pDataWritten = false;
                bool cDataWritten = false;
                bool uDataWritten = false;

                if (CheckServiceState(DumpServices.Cookie) && r.headers.ContainsKey("Cookie"))
                {
                    string cLine = r.headers["Cookie"];

                    if (cLine.Contains(";"))
                    {
                        foreach (string cookie in cLine.Split(';'))
                        {
                            string key = cookie.Split('=')[0];
                            string value = cookie.Split('=')[1];
                            string full = "Cookie:\r\nKey: " + key + "\r\nValue: " + value + "\r\n";
                            fullCookieDump += full;
                            if (!cDataWritten) cDataWritten = true;
                        }
                    }
                    else
                    {
                        string key = cLine.Split('=')[0];
                        string value = cLine.Split('=')[1];
                        string full = "Cookie:\r\nKey: " + key + "\r\nValue: " + value + "\r\n";
                        fullCookieDump += full;
                        cDataWritten = true;
                    }
                }

                if (CheckServiceState(DumpServices.GetParameters))
                {
                    string url = r.target;
                    if (r.target.Contains("?"))
                    {
                        string gp = r.target.Substring(r.target.IndexOf('?') + 1);
                        fullParameterDump += "[GET] Parameters:\r\n";
                        if (gp.Contains("&"))
                        {
                            foreach (string p in gp.Split('&'))
                            {
                                string key = p.Split('=')[0];
                                string value = p.Split('=')[1];
                                string full = "Key: " + key + "\r\nValue: " + value + "\r\n";
                                fullParameterDump += full;
                                if (!pDataWritten) pDataWritten = true;
                            }
                        }
                        else
                        {
                            string key = gp.Split('=')[0];
                            string value = gp.Split('=')[1];
                            string full = "Key: " + key + "\r\nValue: " + value + "\r\n";
                            fullParameterDump += full;
                            pDataWritten = true;
                        }
                    }
                }

                if (CheckServiceState(DumpServices.PostParameters))
                {
                    if (r.headers.ContainsKey("Content-Type"))
                    {
                        string cType = r.headers["Content-Type"];
                        if (cType == "application/x-www-form-urlencoded")
                        {
                            string pp = r.htmlBody;
                            fullParameterDump += "[POST] Parameters:\r\n";
                            if (pp.Contains("&"))
                            {
                                foreach (string p in pp.Split('&'))
                                {
                                    string key = p.Split('=')[0];
                                    string value = p.Split('=')[1];
                                    string full = "Key: " + key + "\r\nValue: " + value + "\r\n";
                                    fullParameterDump += full;
                                    if (!pDataWritten) pDataWritten = true;
                                }
                            }
                            else
                            {
                                string key = pp.Split('=')[0];
                                string value = pp.Split('=')[1];
                                string full = "Key: " + key + "\r\nValue: " + value + "\r\n";
                                fullParameterDump += full;
                                pDataWritten = true;
                            }
                        }
                    }
                }

                if (CheckServiceState(DumpServices.Url))
                {
                    string url = r.target;
                    if (url != "")
                    {
                        fullUrlDump += "URL: " + url + "\r\n";
                        uDataWritten = true;
                    }
                }

                string time = DateTime.Now.ToShortDateString() + " " + DateTime.Now.ToShortTimeString();
                string target = r.target;

                if (target.Contains("?")) target = target.Substring(0, target.IndexOf("?"));

                if (cDataWritten)
                {
                    fullCookieDump = time + " -- " + target + "\r\n" + fullCookieDump + "\r\n";
                    dump.Dump(fullCookieDump, "mitm_cookie_store");
                }

                if (pDataWritten)
                {
                    fullParameterDump = time + " -- " + target + "\r\n" + fullParameterDump + "\r\n";
                    dump.Dump(fullParameterDump, "mitm_parameter_store");
                }

                if (uDataWritten)
                {
                    fullUrlDump = time + "\r\n" + fullUrlDump + "\r\n";
                    dump.Dump(fullUrlDump, "mitm_url_store");
                }
            }
        }

        /// <summary>
        /// Dump all data selected based on a Response object using VDump class
        /// </summary>
        /// <param name="r">The current Response object</param>
        /// <param name="senderUrl">The url of the page requested</param>

        public void DumpResponse(Response r, string senderUrl)
        {
            if (IsAllOfflineD()) return;
            string fullCookieDump = "";
            bool cDataWritten = false;

            if (CheckServiceState(DumpServices.SetCookie))
            {
                //Can send multiple Set-Cookie headers
                if (!r.headers.ContainsKey("Set-Cookie")) return;
                string[] schs = ctx.Ie2sa(r.headers.GetMultipleItems("Set-Cookie"));
                foreach (string sc in schs)
                {
                    string cookie = "";
                    if (sc.Contains(";")) cookie = sc.Substring(0, sc.IndexOf(';'));
                    else cookie = sc;
                    string key = cookie.Split('=')[0];
                    string value = cookie.Split('=')[1];
                    fullCookieDump += "Set Cookie:\r\nKey: " + key + " Value: " + value + "\r\n";
                    if (!cDataWritten) cDataWritten = true;
                }
            }

            if (cDataWritten)
            {
                string time = DateTime.Now.ToShortDateString() + " " + DateTime.Now.ToShortTimeString();

                if (cDataWritten)
                {
                    fullCookieDump = time + " -- " + senderUrl + "\r\n" + fullCookieDump + "\r\n";
                    dump.Dump(fullCookieDump, "mitm_cookie_store");
                }
            }
        }

        /// <summary>
        /// Inject the setup payloads to responses (auto or match injection)
        /// </summary>
        /// <param name="rBody">The original response text</param>
        /// <param name="responseType">The Content-Type header</param>
        /// <returns>string to replace to original content with</returns>

        public string Inject(string rBody, string responseType)
        {
            if (rBody == null || rBody == "" || !CheckServiceState(InjectServices.Core)) return null;

            if (CheckServiceState(InjectServices.AutoInjection))
            {
                VInject.Mode m = VInject.Mode.CSS;
                if (responseType.Contains("javascript")) m = VInject.Mode.Javascript;
                else if (responseType.Contains("CSS")) m = VInject.Mode.CSS;
                else m = VInject.Mode.HTML;
                string infected = vi.AutoInject(rBody, vi.autoPayload, m);
                return infected;
            }

            if (CheckServiceState(InjectServices.MatchInjection))
            {
                string pload = vi.GetCurrentPayload();
                if (pload == null) return null;
                string infected = vi.MatchAndInject(rBody, pload, vi.mMode, vi.mOption);
                return infected;
            }

            return null;
        }

        /// <summary>
        /// Does injection with mediaReplace
        /// </summary>
        /// <param name="resp">The current response object</param>
        /// <param name="req">The current request object</param>
        /// <returns>byte array of new media</returns>

        public byte[] MediaRewrite(Response resp, Request req)
        {
            if (resp.bodyText != "" || resp.FullBytes.Length == 0) return null;
            if (!resp.headers.ContainsKey("Content-Type")) return null;
            string mime = resp.headers["Content-Type"];
            bool mimeFilter = vf.RunAllCompareOr("mitm_mime_media", mime);
            if (!mimeFilter) return null;
            else
            {
                bool response = vi.MediaReplace(req, vi.filePathOption);
                if (response)
                {
                    byte[] result = vi.GetMediaHijack(req);
                    return result;
                }
                else return null;
            }
        }

        //Service Related

        public void ListServices()
        {
            int pIndex = 0;

            for (int i = 0; i < blockServices.Length; i++)
            {
                string sName = blockServices[i];
                console.WriteLine(sName + " - " + defs[pIndex], "ig.mitm");
                pIndex++;
            }

            for (int i = 0; i < dumpServices.Length; i++)
            {
                string sName = dumpServices[i];
                console.WriteLine(sName + " - " + defs[pIndex], "ig.mitm");
                pIndex++;
            }

            for (int i = 0; i < injectServices.Length; i++)
            {
                string sName = injectServices[i];
                console.WriteLine(sName + " - " + defs[pIndex], "ig.mitm");
                pIndex++;
            }
        }

        public bool CheckServiceState(BlockServices service)
        {
            int sid = (int)service;
            bool state = bState[sid];
            if (service == BlockServices.Undefined)
            {
                logger.Log("Invalid service name specified!", VLogger.LogLevel.error);
            }
            return state;
        }

        public bool CheckServiceState(DumpServices service)
        {
            int sid = (int)service;
            bool state = dState[sid];
            if (service == DumpServices.Undefined)
            {
                logger.Log("Invalid service name specified!", VLogger.LogLevel.error);
            }
            return state;
        }

        public bool CheckServiceState(InjectServices service)
        {
            if (service == InjectServices.Undefined)
            {
                logger.Log("Invalid service name!", VLogger.LogLevel.error);
                return false;
            }

            int sid = (int)service;
            return iState[sid];
        }

        public void SetServiceState(BlockServices service, bool state)
        {
            int sid = (int)service;
            bState[sid] = state;
            string srvName = blockServices[sid].Substring(4);
            logger.Log("MITM" + srvName + " set to " + ((state) ? "Enabled" : "Disabled"), VLogger.LogLevel.service);
        }

        public void SetServiceState(DumpServices service, bool state)
        {
            int sid = (int)service;
            dState[sid] = state;
            string srvName = dumpServices[sid].Substring(4);
            logger.Log("MITM" + srvName + " set to " + ((state) ? "Enabled" : "Disabled"), VLogger.LogLevel.service);
        }

        public void SetServiceState(InjectServices service, bool state)
        {
            if (service == InjectServices.Undefined)
            {
                logger.Log("Invalid Service name!", VLogger.LogLevel.error);
                return;
            }

            int sid = (int)service;
            iState[sid] = state;
        }

        public bool IsSetServiceCommand(string input)
        {
            string srvString = "";
            if (input.Contains(" ")) srvString = input.Split(' ')[0];
            else srvString = input;

            foreach (string bs in blockServices)
            {
                if (srvString.ToLower() == bs) return true;
            }

            foreach (string ds in dumpServices)
            {
                if (srvString.ToLower() == ds) return true;
            }

            foreach (string iS in injectServices)
            {
                if (srvString.ToLower() == iS) return true;
            }

            return false;
        }

        private bool IsAllOfflineD()
        {
            foreach (bool b in dState)
            {
                if (b == true) return false;
            }

            return true;
        }

        private bool IsAllOfflineB()
        {
            foreach (bool b in bState)
            {
                if (b) return false;
            }

            return true;
        }

        public bool IsAllOfflineI()
        {
            foreach (bool b in iState)
            {
                if (b) return false;
            }

            return true;
        }

        public void SetManager(VFilter vfman)
        {
            vf = vfman;
        }

        public void SetDumpManager(VDump dmp)
        {
            dump = dmp;
        }

        public void SetInjectionManager(VInject inject)
        {
            vi = inject;
        }

        public void SetLogger(VLogger lg)
        {
            logger = lg;
        }

        public string ServiceToString(BlockServices input)
        {
            int sid = (int)input;
            return blockServices[sid];
        }

        public string ServiceToString(DumpServices input)
        {
            int sid = (int)input;
            return dumpServices[sid];
        }

        public string ServiceToString(InjectServices input)
        {
            int sid = (int)input;
            return injectServices[sid];
        }

        public void ListAll(string state)
        {
            state = state.ToLower();
            int index = 0;
            if (state == "online")
            {
                bool written = false;
                console.Write("\r\n");

                foreach (string s in blockServices)
                {
                    if (bState[index])
                    {
                        console.Write("MITM" + s.Substring(4) + ", ");
                        if (!written) written = true;
                    }
                    index++;
                }

                index = 0;

                foreach (string s in dumpServices)
                {
                    if (dState[index])
                    {
                        console.Write("MITM" + s.Substring(4) + ", ");
                        if (!written) written = true;
                    }
                    index++;
                }

                index = 0;

                foreach (string s in injectServices)
                {
                    if (iState[index])
                    {
                        if (injectServices.Length - 1 > index) console.Write("MITM" + s.Substring(4) + ", ");
                        else console.Write("MITM" + s.Substring(4));
                        if (!written) written = true;
                    }

                    index++;
                }

                if (!written) console.WriteLine("No services are online at this moment!", console.GetIntercativeGroup());

                if (written) console.Write("\r\n");
            }
            else if (state == "offline")
            {
                bool written = false;
                console.Write("\r\n");

                foreach (string s in blockServices)
                {
                    if (!bState[index])
                    {
                        console.Write("MITM" + s.Substring(4) + ", ");
                        if (!written) written = true;
                    }
                    index++;
                }

                index = 0;

                foreach (string s in dumpServices)
                {
                    if (!dState[index])
                    {
                        console.Write("MITM" + s.Substring(4) + ", ");
                        if (!written) written = true;
                    }
                    index++;
                }

                index = 0;

                foreach (string s in injectServices)
                {
                    if (!iState[index])
                    {
                        if (injectServices.Length - 1 > index) console.Write("MITM" + s.Substring(4) + ", ");
                        else console.Write("MITM" + s.Substring(4));
                        if (!written) written = true;
                    }
                    index++;
                }

                if (!written) console.WriteLine("No services are offline at this moment!", console.GetIntercativeGroup());

                if (written) console.Write("\r\n");
            }
            else
            {
                logger.Log("Invalid state parameter!", VLogger.LogLevel.error);
            }
        }

        public BlockServices StringToBService(string input)
        {
            int currentIndex = 0;
            bool ciSet = false;

            foreach (string s in blockServices)
            {
                if (s == input.ToLower())
                {
                    ciSet = true;
                    break;
                }
                currentIndex++;
            }

            if (ciSet) return (BlockServices)currentIndex;
            else return BlockServices.Undefined;
        }

        public DumpServices StringToDService(string input)
        {
            int currentIndex = 0;
            bool ciSet = false;

            foreach (string s in dumpServices)
            {
                if (s == input.ToLower())
                {
                    ciSet = true;
                    break;
                }
                currentIndex++;
            }

            if (ciSet) return (DumpServices)currentIndex;
            else return DumpServices.Undefined;
        }

        public InjectServices StringToIService(string input)
        {
            int currentIndex = 0;
            bool ciSet = false;

            foreach (string s in injectServices)
            {
                if (s == input.ToLower())
                {
                    ciSet = true;
                    break;
                }
                currentIndex++;
            }

            if (ciSet) return (InjectServices)currentIndex;
            else return InjectServices.Undefined;
        }
    }

}
